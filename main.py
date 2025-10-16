import argparse, os
from torch.utils.data import DataLoader

from config import config
from data import *
from train import *
from utils import *

def main():
    parser = argparse.ArgumentParser(description="Run the model in train/resume/generate mode.")
    parser.add_argument(
        "mode",
        type=str,
        choices=["train", "resume", "generate"],  # Only allow these 3 options
        help="Mode to run the program: 'train', 'resume', or 'generate'"
    )
    parser.add_argument(
        "--input_dir",
        type=str,
        required=False,  # Not required by default
        help="Path to input directory (required for 'train' or 'resume')"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        help="Path to save model checkpoints (required for train/resume)"
    )
    parser.add_argument(
        "--checkpoint_path",
        help="Path to model required for generate)"
    )
    args = parser.parse_args()

    if args.mode in ["resume", "generate"]:
        if not args.checkpoint_path:
            parser.error("--checkpoint_path is required for resume/generate")
        if not os.path.exists(args.checkpoint_path):
            parser.error(f"Checkpoint not found at {args.checkpoint_path}")
    if args.mode in ["train", "resume"]:
        if not args.input_dir:
            parser.error("--input_dir is required for train/resume")
    if args.mode in ["train", "resume"]:
        if not args.output_dir:
            parser.error("--output_dir is required for train/resume")

        config['data_path'] = args.input_dir
        config['num_workers'] = os.cpu_count()

        # Prepare Data
        train_data, val_data = prepare_datasets(config)
        train_dataset = PreprocessedDataset(train_data, config['context_length'])
        val_dataset = PreprocessedDataset(val_data, config['context_length'])

        # Optimized DataLoader setup
        train_loader = DataLoader(
            train_dataset,
            batch_size=config['batch_size'],
            shuffle=True,
            collate_fn=collate_fn,
            num_workers=config['num_workers'], 
            pin_memory=True,
            persistent_workers=True,  # Keep workers alive
            prefetch_factor=8,  # Preload batches
        )

        val_loader = DataLoader(
            val_dataset,
            batch_size=config['batch_size'],
            shuffle=True,
            collate_fn=collate_fn,
            num_workers=config['num_workers'], 
            pin_memory=True,
            persistent_workers=True,  # Keep workers alive
            prefetch_factor=8  # Preload batches
        )

    if args.mode == "train":
        model = TCPHeaderTransformer(
            vocab_size=65546,
            d_model=config['d_model'],
            nhead=config['nhead'],
            num_layers=config['num_layers'],
            dim_feedforward=config['dim_feedforward'],
            dropout=config['dropout']
        ).to(config['device'])
        # model = torch.compile(model)

        train(model, train_loader, val_loader, config)

        os.makedirs(args.output_dir, exist_ok=True)
        model_save_path = os.path.join(args.output_dir, "tcp_flow_gen2.pth")
        torch.save({
        'model_state_dict': model.state_dict(),
        'config': config  # Save your hyperparameters too
        }, model_save_path)

    elif args.mode == "resume":
        resume_training(
        checkpoint_path=args.checkpoint_path,
        num_epochs=20,
        train_loader=train_loader,
        val_loader=val_loader
        )

    elif args.mode == "generate":
        if not args.output_dir:
            parser.error("--output_dir required to store arrow file")
        
        model, loaded_config = load_model(args.checkpoint_path)
        
        # Generate sample
        start_tokens = [65536, 65540, 65543]
        steps = loaded_config['context_length'] - len(start_tokens)
        tokens_list = []
        num_flows=500
        for i in range(num_flows):
            model.reset_state()
            if i > 0:
                torch.cuda.empty_cache() if torch.cuda.is_available() else None
            with torch.no_grad():
                # Take the first sequence from start_tokens and use steps instead of max_len
                generated = model.generate(start_tokens, steps=steps, repetition_penalty=1.15)
                tokens = generated.cpu().tolist()
                tokens_list.append(tokens)
                #print(f"Generated flow {i+1}: {tokens[:10]}... (length: {len(tokens)})")
                print(f"Generated flow {i+1}: {tokens}\n(length: {len(tokens)})")
        
        filename = "gen_tokens.arrow"
        path = args.output_dir
        file_path = os.path.join(path, filename)
        arrow_constructor(tokens_list, file_path)

if __name__ == '__main__':
    main()
