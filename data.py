import torch, os
import numpy as np
from config import config
from datasets import load_dataset
from torch.utils.data import Dataset

def analyze_token_lengths(config,dataset):
    bins = [int(config['context_length'] * x) for x in [0, 0.25, 0.5, 0.75, 1, 1.25, 1.5, 1.75, 2, 5]] + [float('inf')]
    bin_labels = [f"0-{bins[1]}", 
                 f"{bins[1]+1}-{bins[2]}", 
                 f"{bins[2]+1}-{bins[3]}", 
                 f"{bins[3]+1}-{bins[4]}",
                 f"{bins[4]+1}-{bins[5]}", 
                 f"{bins[5]+1}-{bins[6]}", 
                 f"{bins[6]+1}-{bins[7]}", 
                 f"{bins[7]+1}-{bins[8]}", 
                 f"{bins[8]+1}-{bins[9]}", 
                 f"{bins[9]}+"]
    counts = {label: 0 for label in bin_labels}
    #print(counts)

    for example in dataset:
        token_length = len(example["token_sequences"])        
        for i in range(len(bins)-1):
            if bins[i] < token_length <= bins[i+1]:
                counts[bin_labels[i]] += 1
                break
    
    return counts

def print_token_length_analysis(counts):
    print("\nToken Length Categories:")
    print("----------------------------------")
    total = sum(counts.values())
    for bin_label, count in counts.items():
        percentage = (count / total) * 100 if total > 0 else 0
        print(f"{bin_label}: {count} sequences ({percentage:.2f}%)")
    print("----------------------------------")
    print(f"Total sequences: {total}")

def prepare_datasets(config):
    # Load all Arrow files
    print(config['data_path'])
    all_files = [
        os.path.join(config['data_path'], f)
        for f in os.listdir(config['data_path'])
        if f.endswith(".arrow")
    ]

    dataset = load_dataset("arrow", data_files=all_files, split="train")
    # token_length_counts = analyze_token_lengths(config,dataset)
    # print_token_length_analysis(token_length_counts)
    
    def apply_sliding_window(examples):
        stride = config['context_length'] // 2
        new_sequences = []
        for tokens in examples["token_sequences"]:
            if len(tokens) > config['context_length']:
                for start in range(0, len(tokens) - config['context_length'], stride):
                    window = tokens[start : start + config['context_length']]
                    new_sequences.append(window)
                context_length = config['context_length']
                if start + context_length < len(tokens):
                    #print(len(tokens[start + context_length:]))
                    new_sequences.append(tokens[-context_length:])
            else:
                new_sequences.append(tokens)

        return {"token_sequences": new_sequences}

    def filter_sequences(examples):
        filtered_sequences = [
            seq for seq in examples["token_sequences"]
            if len(seq) <= config['filter_length'] + 1
        ]
        return {"token_sequences": filtered_sequences}

    dataset = dataset.map(filter_sequences, batched=True)
    dataset = dataset.map(apply_sliding_window, batched=True, remove_columns=dataset.column_names)
    dataset = dataset.flatten_indices()  # flatten examples
    # token_length_counts = analyze_token_lengths(config,dataset)
    # print_token_length_analysis(token_length_counts)
    split = dataset.train_test_split(test_size=0.1, seed=config['seed'])

    return split["train"], split["test"]

def collate_fn(batch):
    context_length = config['context_length']
    pad_token = 65545
    x_batch = torch.full((len(batch), context_length), pad_token, dtype=torch.long)
    y_batch = torch.full((len(batch), context_length), pad_token, dtype=torch.long)

    for i, item in enumerate(batch):
        tokens = item["tokens"]
        seq_len = len(tokens)

        x_batch[i, :seq_len-1] = torch.tensor(tokens[:-1])
        y_batch[i, :seq_len-1] = torch.tensor(tokens[1:])

    return x_batch, y_batch

class PreprocessedDataset(Dataset):
    def __init__(self, data, context_length=1024, pad_token=65545):
        self.data = data
        self.context_length = context_length
        self.pad_token = pad_token

    def __getitem__(self, index):
        # Return raw data for batch processing
        return {
            "tokens": self.data[index]["token_sequences"],
            "length": len(self.data[index]["token_sequences"])
        }

    def __len__(self):
        return len(self.data)
