import numpy as np
import os, random, json, torch
import torch.nn as nn
import torch.nn.functional as F
from torch.optim import AdamW
from torch.nn.utils import clip_grad_norm_
from torch.nn import CrossEntropyLoss  
from torch.optim.lr_scheduler import LambdaLR
from tqdm import tqdm

from data import *
from model import *
from utils import *
from config import config

os.environ['PYTORCH_CUDA_ALLOC_CONF'] = 'expandable_segments:True'
torch._dynamo.config.capture_scalar_outputs = True  # Fixes the .item() break
torch._dynamo.config.suppress_errors = True  # Temporarily for debugging
torch.backends.cudnn.benchmark = True  # Optimize convolutions for GPU
torch.set_float32_matmul_precision('high') # numerical stability for transformers

torch.manual_seed(config['seed'])
np.random.seed(config['seed'])
random.seed(config['seed'])

def evaluate(model, dataloader, device='cuda'):
    # model.to(device)  # Ensure model is on device
    model.eval()
    total_loss, total_correct, total_non_padded = 0, 0, 0
    criterion = nn.CrossEntropyLoss(ignore_index=65545, reduction='sum')

    with torch.no_grad():
        for x, y in dataloader:
            x, y = x.to(device, non_blocking=True), y.to(device, non_blocking=True)

            with torch.autocast(device_type=device.split(':')[0], dtype=torch.float16):  # Mixed precision
                logits = model(x)
                loss = criterion(logits.view(-1, logits.size(-1)), y.view(-1))

            total_loss += loss.item()

            # Calculate accuracy
            preds = logits.argmax(-1)
            mask = y != 65545
            batch_non_padded = mask.sum().item()
            total_non_padded += batch_non_padded
            total_correct += (preds[mask] == y[mask]).sum().item()

    avg_loss = total_loss / total_non_padded if total_non_padded > 0 else 0
    accuracy = total_correct / total_non_padded if total_non_padded > 0 else 0
    return avg_loss, accuracy

def train(model, train_loader, val_loader, config, start_epoch=0, best_val_loss=float('inf')):
    early_exit = False # For when the model stagnates during training
    exit_counter = 0

    torch.backends.cuda.enable_mem_efficient_sdp(True)
    optimizer = AdamW(model.parameters(), lr=config['lr'], fused=True)
    criterion = CrossEntropyLoss(ignore_index=65545)
    scaler = torch.amp.GradScaler('cuda') # Mixed Precision

    warmup_steps = len(train_loader) * config['warmup_epochs']
    scheduler = LambdaLR(optimizer, lambda step: min(step / warmup_steps, 1.0))

    for epoch in range(start_epoch, start_epoch + config['epochs']):
        if early_exit:
            print("Early exit due to poor training improvements")
            break

        model.train()
        total_loss = 0
        count_batch = 0

        train_bar = tqdm(total=len(train_loader), desc=f"Epoch {epoch+1}/{config['epochs']}")

        for i, (x, y) in enumerate(train_loader):
            # Autocast block
            with torch.autocast('cuda', dtype=torch.float16):
              # Async data transfer
              x = x.to(config['device'], non_blocking=True)
              y = y.to(config['device'], non_blocking=True)
              logits = model(x)
              full_loss = criterion(logits.view(-1, logits.size(-1)), y.view(-1))
              loss = full_loss / config['accum_steps']  # For gradient accumulation

            scaler.scale(loss).backward()
            total_loss += full_loss.item()
            train_bar.set_postfix(loss=f"{full_loss.item():.4f}")  # Show original loss
            count_batch +=1

            if count_batch == config['accum_steps']:

              # Gradient clipping
              scaler.unscale_(optimizer)
              clip_grad_norm_(model.parameters(), config['max_grad_norm'])
              # Optimizer
              scaler.step(optimizer)
              scaler.update()
              optimizer.zero_grad(set_to_none=True)
              scheduler.step()
              count_batch=0

              # Update progress bar
              train_bar.set_postfix(loss=f"{full_loss.item():.4f}")
              train_bar.update(config['accum_steps'])

        if count_batch > 0: # Do a final gradient update if the final batch(es) weren't divisible by accum_steps
          scaler.unscale_(optimizer)
          clip_grad_norm_(model.parameters(), config['max_grad_norm'])
          scaler.step(optimizer)
          scaler.update()
          optimizer.zero_grad(set_to_none=True)
          scheduler.step()

          train_bar.update(count_batch % config['accum_steps'])
        train_bar.close()

        avg_train_loss = total_loss / len(train_loader)

        # Validation
        val_loss, val_acc = evaluate(model, val_loader, config['device'])

        if epoch == start_epoch:
            log_file = setup_logging(config)
        with open(log_file, 'r') as f:
            log_data = json.load(f)
        
        log_data['metrics']['epochs'].append(epoch + 1)
        log_data['metrics']['train_loss'].append(avg_train_loss)
        log_data['metrics']['val_loss'].append(val_loss)
        log_data['metrics']['val_acc'].append(val_acc)
        
        with open(log_file, 'w') as f:
            json.dump(log_data, f, indent=2)

        # Save checkpoint
        if (best_val_loss - val_loss) > config['min_improve'] :
          exit_counter = 0
          best_val_loss = val_loss
          torch.save({
              'epoch': epoch,
              'model_state_dict': model.state_dict(),
              'optimizer_state_dict': optimizer.state_dict(),
              'best_val_loss': best_val_loss,
              'loss': val_loss,
              'config': config,
          }, f"./models/checkpoints/tcp_flow_checkpoint_epoch_{epoch+1}.pth")
        else:
          exit_counter +=1
        print(f"Epoch {epoch+1}: Train Loss={avg_train_loss:.4f}, Val Loss={val_loss:.4f}, Val Acc={val_acc:.4f}")

        if exit_counter > config['epoch_treshold'] :
            early_exit = True
            break

def resume_training(checkpoint_path, num_epochs, train_loader, val_loader):
    checkpoint = torch.load(checkpoint_path)
    #print("Checkpoint keys:", checkpoint.keys())  
    loaded_config = checkpoint['config']
    current_config = config
    for key in current_config:
        if key not in loaded_config:
            loaded_config[key] = current_config[key]
    loaded_config['epochs'] = num_epochs  
    best_val_loss = checkpoint['best_val_loss']
    start_epoch = checkpoint['epoch'] + 1

    # Reinitialize model
    model = TCPHeaderTransformer(
        vocab_size=loaded_config['vocab_size'],
        d_model=loaded_config['d_model'],
        nhead=loaded_config['nhead'],
        num_layers=loaded_config['num_layers'],
        dim_feedforward=loaded_config['dim_feedforward'],
        dropout=loaded_config['dropout']
    ).to(loaded_config['device'])

    # Load states - need to strip the _orig_mod prefix
    state_dict = checkpoint['model_state_dict']

    fixed_state_dict = {}
    for key, value in state_dict.items():
        if key.startswith('_orig_mod.'):
            new_key = key[len('_orig_mod.'):]
            fixed_state_dict[new_key] = value
        else:
            fixed_state_dict[key] = value

    # Load the fixed state dict
    model.load_state_dict(fixed_state_dict)

    # Use a more compatible compile mode - 'reduce-overhead' or 'default' is safer
    compiled_model = torch.compile(model, mode='reduce-overhead')

    optimizer = AdamW(model.parameters(), lr=loaded_config['lr'], fused=True)
    optimizer.load_state_dict(checkpoint['optimizer_state_dict'])

    # Create a modified version of the train function that handles compiled models
    def train_compiled(compiled_model, train_loader, val_loader, config, start_epoch, best_val_loss):
        early_exit = False # For when the model stagnates during training
        exit_counter = 0
        torch.backends.cuda.enable_mem_efficient_sdp(True)
        model = compiled_model._orig_mod if hasattr(compiled_model, '_orig_mod') else compiled_model

        for epoch in range(start_epoch, start_epoch + config['epochs']):
            if early_exit:
                print("Early exit due to poor training improvements")
                break
            model.train()  # Set to training mode
            total_loss = 0
            count_batch = 0

            # Add tqdm progress bar
            train_bar = tqdm(total=len(train_loader), desc=f"Epoch {epoch+1}/{start_epoch + config['epochs']}")

            for i, (x, y) in enumerate(train_loader):
                with torch.autocast('cuda', dtype=torch.float16):
                    # Async data transfer
                    x = x.to(config['device'], non_blocking=True)
                    y = y.to(config['device'], non_blocking=True)

                    # Use the compiled_model directly for inference
                    logits = compiled_model(x)
                    criterion = CrossEntropyLoss(ignore_index=65545)
                    full_loss = criterion(logits.view(-1, logits.size(-1)), y.view(-1))
                    loss = full_loss / config['accum_steps']  # For gradient accumulation

                # Use scaler from outer scope
                scaler.scale(loss).backward()
                total_loss += full_loss.item()
                train_bar.set_postfix(loss=f"{full_loss.item():.4f}")  # Show original loss
                count_batch += 1

                if count_batch == config['accum_steps']:
                    # Gradient clipping
                    scaler.unscale_(optimizer)
                    clip_grad_norm_(model.parameters(), config['max_grad_norm'])
                    # Optimizer
                    scaler.step(optimizer)
                    scaler.update()
                    optimizer.zero_grad(set_to_none=True)
                    scheduler.step()
                    count_batch = 0

                    # Update progress bar
                    train_bar.set_postfix(loss=f"{full_loss.item():.4f}")
                    train_bar.update(config['accum_steps'])

            if count_batch > 0:  # Do a final gradient update if needed
                scaler.unscale_(optimizer)
                clip_grad_norm_(model.parameters(), config['max_grad_norm'])
                scaler.step(optimizer)
                scaler.update()
                optimizer.zero_grad(set_to_none=True)
                scheduler.step()

                train_bar.update(count_batch % config['accum_steps'])
            train_bar.close()

            avg_train_loss = total_loss / len(train_loader)

            # For evaluation, we should use the original model
            val_loss, val_acc = evaluate(model, val_loader, config['device'])

            if epoch == start_epoch:
                log_file = setup_logging(config)
            with open(log_file, 'r') as f:
                log_data = json.load(f)
        
            log_data['metrics']['epochs'].append(epoch + 1)
            log_data['metrics']['train_loss'].append(avg_train_loss)
            log_data['metrics']['val_loss'].append(val_loss)
            log_data['metrics']['val_acc'].append(val_acc)
            
            with open(log_file, 'w') as f:
                json.dump(log_data, f, indent=2)

            # Save checkpoint
            if (best_val_loss - val_loss) > config['min_improve'] :
                exit_counter = 0 
                best_val_loss = val_loss
                torch.save({
                    'epoch': epoch,
                    'model_state_dict': model.state_dict(),
                    'optimizer_state_dict': optimizer.state_dict(),
                    'best_val_loss': best_val_loss,
                    'loss': val_loss,
                    'config': config,
                }, f"./models/checkpoints/tcp_flow_checkpoint_epoch_{epoch+1}.pth")
            else:
                exit_counter +=1
            print(f"Epoch {epoch+1}: Train Loss={avg_train_loss:.4f}, Val Loss={val_loss:.4f}, Val Acc={val_acc:.4f}")

            if exit_counter > config['epoch_treshold'] :
                early_exit = True
                break
    # Setup optimizer and scaler
    criterion = CrossEntropyLoss(ignore_index=65545)
    scaler = torch.amp.GradScaler('cuda')

    warmup_steps = len(train_loader) * loaded_config['warmup_epochs']
    scheduler = LambdaLR(optimizer, lambda step: min(step / warmup_steps, 1.0))
    train_compiled(compiled_model, train_loader, val_loader, loaded_config, start_epoch, best_val_loss)

