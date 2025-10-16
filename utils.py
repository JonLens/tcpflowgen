import json, os, torch
import pyarrow as pa
import numpy as np
from datetime import datetime
from model import *

def load_model(path):
    """Load and return a trained model from checkpoint."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Checkpoint not found at {path}")
    
    checkpoint = torch.load(path)
    loaded_config = checkpoint['config']
    
    model = TCPHeaderTransformer(
        vocab_size=loaded_config['vocab_size'],
        d_model=loaded_config['d_model'],
        nhead=loaded_config['nhead'],
        num_layers=loaded_config['num_layers'],
        dim_feedforward=loaded_config['dim_feedforward'],
        dropout=loaded_config['dropout']
    ).to(loaded_config['device'])
    
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    
    return model, loaded_config

def setup_logging(config):
    """Setup logging to a JSON file with timestamp"""
    log_dir = "./logs"
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"training_log_{timestamp}.json")

    # Initialize log file with config and empty metrics
    log_data = {   
        "config": config,
        "metrics": {  
            "train_loss": [],
            "val_loss": [],
            "val_acc": [],
            "epochs": []
        }
    }

    with open(log_file, 'w') as f:
        json.dump(log_data, f, indent=2)

    return log_file

def arrow_constructor(tokens_list, output_path):
    """
    Save multiple token sequences (flows) to an Arrow file in list<Int32> format.
    Matches exactly what the C++ loader expects.
               
    Args:
         tokens_list: List of token sequences (each sequence is a list of integers)
         output_path: Path to save the Arrow file
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    list_array = pa.array(tokens_list, type=pa.list_(pa.int32()))
    table = pa.Table.from_arrays([list_array], names=["flows"])

    with pa.OSFile(output_path, 'wb') as sink:
        with pa.ipc.RecordBatchFileWriter(sink, table.schema) as writer:
            writer.write_table(table)

    print(f"Successfully saved {len(tokens_list)} flows to {output_path}")
    return
