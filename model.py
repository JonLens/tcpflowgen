import torch
import torch.nn as nn
import torch.nn.functional as F
from fast_transformers.attention.causal_linear_attention import CausalLinearAttention
from fast_transformers.masking import LengthMask, TriangularCausalMask
from torchtune.modules import RotaryPositionalEmbeddings
from torch.utils.checkpoint import checkpoint

class CausalLinearTransformerDecoderLayer(nn.Module):
    def __init__(self, d_model, nhead, dim_feedforward=2048, dropout=0.1, max_seq_len=4096, max_padded_length=1024):
        super().__init__()
        # self._cached_mask = None
        # self._cached_mask_len = 0

        self.max_padded_length = max_padded_length
        self.d_model = d_model
        self.nhead = nhead
        self.head_dim = d_model // nhead

        # self.qkv_proj = nn.Linear(d_model, 3 * d_model)
        self.q_proj = nn.Linear(d_model, d_model)
        self.k_proj = nn.Linear(d_model, d_model)
        self.v_proj = nn.Linear(d_model, d_model)

        # Causal Linear Attention
        self.self_attn = CausalLinearAttention(
            query_dimensions=self.head_dim
        )

        # Rotary Positional Embeddings from torchtune
        self.rotary_emb = RotaryPositionalEmbeddings(
            dim=self.head_dim,
            max_seq_len=max_seq_len
        )

        # Feedforward layers
        self.linear1 = nn.Linear(d_model, dim_feedforward)
        self.linear2 = nn.Linear(dim_feedforward, d_model)

        # Normalization
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)

        # Dropout
        self.dropout = nn.Dropout(dropout)
        self.activation = nn.GELU()

    def _forward(self, tgt, tgt_mask=None, padding_mask=None):
        """Forward pass with causal attention and rotary embeddings"""
        
        # Create masks
        causal_mask = TriangularCausalMask(tgt.size(1), device=tgt.device)
        lengths = (~padding_mask).sum(dim=1).long().to(tgt.device)
        length_mask = LengthMask(lengths, max_len=tgt.size(1))

        # Apply layer norm
        norm_tgt = self.norm1(tgt)
        B, L, _ = norm_tgt.shape
        q = self.q_proj(norm_tgt)
        k = self.k_proj(norm_tgt)
        v = self.v_proj(norm_tgt)
        q = q.view(B, L, self.nhead, self.head_dim)  # [B, L, H, D/H]
        k = k.view(B, L, self.nhead, self.head_dim)  # [B, L, H, D/H]
        v = v.view(B, L, self.nhead, self.head_dim)  # [B, L, H, D/H]

        # Apply rotary embeddings to queries and keys
        q = self.rotary_emb(q)
        k = self.rotary_emb(k)

        # Reshape for multi-head attention
        v = v.view(B, L, self.nhead, self.head_dim)
        original_dtype = q.dtype

        # Convert to float32 for causal attention
        q, k, v = q.float(), k.float(), v.float()
        # Causal attention
        attn_out = self.self_attn(
            q, k, v,  # Now using separate V
            attn_mask=causal_mask,
            query_lengths=length_mask,
            key_lengths=length_mask
        )
        attn_out = attn_out.to(original_dtype) # Restore to float16
        attn_out = attn_out.view(B, L, self.d_model) # [B, L, H, D/H] -> [B, L, D]
        tgt = tgt + self.dropout(attn_out)

        # Feedforward
        ff_out = self.linear2(self.dropout(self.activation(self.linear1(self.norm2(tgt)))))
        tgt = tgt + self.dropout(ff_out)
        return tgt

    def forward(self, tgt, tgt_mask=None, padding_mask=None):
        """Checkpointed forward pass"""
        #print(f"Grad status - tgt: {tgt.requires_grad}, mask: {tgt_mask.requires_grad if tgt_mask is not None else None}")
        # tgt = tgt.requires_grad_(True)
        # print(f"Grad status - tgt: {tgt.requires_grad}, mask: {tgt_mask.requires_grad if tgt_mask is not None else None}")

        return checkpoint(self._forward, tgt, tgt_mask, padding_mask, use_reentrant=False) # original: use_reentrant=False

"""## Decoder Architecture"""

class TCPHeaderTransformer(nn.Module):
    def __init__(self, vocab_size=65546, d_model=256, nhead=8, num_layers=8,
                 dim_feedforward=1024, dropout=0.1, max_seq_len=4096, max_padded_length=1024):
        super().__init__()
        self.vocab_size = vocab_size
        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=65545)
        self.padding_idx = 65545
        # Use our causal layers with rotary embeddings
        self.layers = nn.ModuleList([
            CausalLinearTransformerDecoderLayer(
                d_model=d_model,
                nhead=nhead,
                dim_feedforward=dim_feedforward,
                dropout=dropout,
                max_seq_len=max_seq_len
                # max_padded_length=max_padded_length
            ) for _ in range(num_layers)
        ])

        self.output = nn.Sequential(
            nn.LayerNorm(d_model),
            nn.Linear(d_model, vocab_size)
        )
        self.dropout = nn.Dropout(dropout)

    def forward(self, x, padding_mask=None):
        if padding_mask is None:
          padding_mask = (x == self.padding_idx)
        else:
          # Verify padding_mask has correct shape
          assert padding_mask.shape == x.shape, (
              f"Padding mask shape {padding_mask.shape} "
              f"doesn't match input shape {x.shape}"
          )
        x = self.embedding(x)
        x = x.requires_grad_(True)
        x = self.dropout(x)

        for layer in self.layers:
            x = layer(x, padding_mask=padding_mask)

        return self.output(x)

    def reset_state(self):
        """Reset any internal state for fresh generation"""
        # Clear any cached states in layers
        for layer in self.layers:
            if hasattr(layer, 'self_attn') and hasattr(layer.self_attn, 'feature_map'):
                # Reset causal linear attention internal state if it exists
                if hasattr(layer.self_attn, '_reset_state'):
                    layer.self_attn._reset_state()
            # Clear any cached masks or states
            if hasattr(layer, '_cached_mask'):
                layer._cached_mask = None
                layer._cached_mask_len = 0

    def generate(self, initial_token, steps=100, temperature=0.7, top_k=50, 
                                repetition_penalty=1.1, max_context_len=1024):
        """Ultra memory-efficient single sequence generation"""
        with torch.inference_mode():
            self.eval()
            device = next(self.parameters()).device
            
            if isinstance(initial_token, list):
                x = torch.tensor(initial_token, device=device).unsqueeze(0)
                generated = initial_token.copy()
            else:
                x = initial_token.unsqueeze(0) if initial_token.dim() == 1 else initial_token
                generated = x.squeeze().tolist()
                if not isinstance(generated, list):
                    generated = [generated]
            
            seen_tokens = set(generated) if repetition_penalty != 1.0 else None
            
            for step in range(steps):
                # Sliding window
                if x.size(1) > max_context_len:
                    x = x[:, -max_context_len:]
                
                # Mixed precision forward
                with torch.autocast(device_type='cuda', dtype=torch.float16):
                    logits = self(x)[:, -1]
                
                # Fast repetition penalty
                if repetition_penalty != 1.0 and seen_tokens:
                    penalty_indices = torch.tensor(list(seen_tokens), device=device, dtype=torch.long)
                    logits[0, penalty_indices] /= repetition_penalty
                
                logits /= temperature
                top_k_values, top_k_indices = torch.topk(logits, top_k)
                probs = F.softmax(top_k_values, dim=-1)
                next_token_idx = torch.multinomial(probs, num_samples=1)
                next_token = top_k_indices.gather(-1, next_token_idx).squeeze()
                
                next_token_item = next_token.item()
                generated.append(next_token_item)
                
                if seen_tokens is not None:
                    seen_tokens.add(next_token_item)
                
                x = torch.cat([x, next_token.unsqueeze(0).unsqueeze(0)], dim=1)
                
                # Clear cache periodically
                if step % 100 == 0:
                    torch.cuda.empty_cache()
            
            return torch.tensor(generated, device=device)
