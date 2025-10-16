# config.py
import torch

config = {
  'data_path': './drive/MyDrive/mawilab_lim/',
  'batch_size': 16,
  'accum_steps': 4,
  'd_model': 256,
  'nhead': 8,
  'num_layers': 8,
  'dim_feedforward': 1024,
  'dropout': 0.1,
  'epochs': 10,
  'lr': 1e-4,
  'max_grad_norm': 1.0,
  'context_length': 1024,
  'vocab_size': 65546,
  'warmup_epochs': 2,
  'num_workers': 2,
  'seed': 42,
  'filter_length': 2048,
  'min_improve' : 0.001,
  'epoch_treshold' : 3,
  'device': 'cuda' if torch.cuda.is_available() else 'cpu'
}
