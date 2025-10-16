# TCP header Generation
## Description
Linear Transformer model that is able to generate TCP flows that can be interpreted as a PCAP file.

This repository is built out of two parts. The CPP project is used to extract complete TCP flows from a given set of input PCAP files and then encodes them to be used as training data for the model.
The python part then trains the model and is able to generate TCP flows. The generated tokens can then be used by the CPP project to decode them into valid pcap files containing TCP flows.

## Usage
Note, this only works for Linux.

### Pre-processing and Post-Processing (C++)
#### Install vcpkg
Best to do this in the home folder. Don't forget to add the location of vcpkg to the PATH
```
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg integrate install
```
Add this to your ./bashrc:
```
export PATH=$PATH:~/vcpkg
export VCPKG_ROOT=~/vcpkg
```

#### Install C++ packages
First check the neccesary pacakges are already installed
```
sudo apt install -y build-essential cmake ninja-build pkg-config flex bison
```

```
vcpkg install
```
Add this if there's an issue with the baseline:
```
vcpkg x-update-baseline --add-initial-baseline
```

#### Build the project
```
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake
cmake --build build
```
#### Usage of the program
##### Encode Mode
The encode mode is used to anaylze a pcap file (or folder) for complete TCP flows and store them into arrow files.
```
./build/tcp_flow_processor encode <input_pcap_or_directory> <output_arrow_directory>
```
##### Decode Mode
The decode mode is for converting your generated tokens that are stored in arrow files to pcap files.
```
./build/tcp_flow_processor decode <input_arrow_directory> <output_pcap_directory>
```

### Training and Generation (Python)

#### Setup
It is best to run this in a conda environment:
```
conda create -n tcpflowgen python=3.12
conda activate tcpflowgen
```
Install the the following packages in conda:
```
conda install -c conda-forge gxx_linux-64=11.3.0 ninja cmake -y
conda install -c "nvidia/label/cuda-12.4.0" \
    cuda-toolkit=12.4 \
    cuda-nvcc=12.4 \
    cuda-cudart=12.4 \
    cuda-libraries-dev=12.4 \
    -y
```
Install the correct torch version
```
pip install \
    torch==2.6.0 \
    --index-url https://download.pytorch.org/whl/cu124
pip install torchtune==0.6.0 torchao==0.1.0
```
Point conda to the correct environment:
```
export CUDA_HOME=$CONDA_PREFIX
export PATH=$CUDA_HOME/bin:$PATH
export LD_LIBRARY_PATH=$CUDA_HOME/lib64:$LD_LIBRARY_PATH

FORCE_CUDA=1 \
TORCH_CUDA_ARCH_LIST="8.6" \
CC=$CONDA_PREFIX/bin/x86_64-conda-linux-gnu-cc \
CXX=$CONDA_PREFIX/bin/x86_64-conda-linux-gnu-c++ \
```
Install the fast transformers repo and other requirements
```
git clone https://github.com/idiap/fast-transformers.git
cd fast-transformers
pip install -e . --no-build-isolation -v
cd ..
pip install -r requirements.txt 
```

Start the program by running main.py\
There're three modes:

#### Training

```
python3 main.py train --input_dir <arrow_files_dir> --output_dir <models_dir> 
```

#### Resume training
Continue training the model from a given checkpoint:
```
python3 main.py resume --checkpoint_path <checkpoint_path> --input_dir <arrow_files_dir> --output_dir <models_dir>
```

#### Generate
```
python3 main.py generate --checkpoint_path <model_path> --output_dir <output_pcap_directory>
```

## Background:
Over the past decades, machine learning (ML) methods have been extensively used for network traffic analysis for tasks such as encrypted traffic classification, OS and protocol identification, network intrusion detection, and more. Despite achieving notable performance in lab settings, many studies face challenges, including inconsistent designs, limited evaluation practices, and poor-quality data. This lack of standardization in methods and datasets has led to issues in replicability and real-world applicability of results. Currently, there is an ongoing effort to create comprehensive evaluation frameworks for ML-based traffic analysis. This thesis aims to contribute to this endeavor by exploring a novel approach: using foundational models (typically employed in natural language processing) to generate and analyze network traffic data, ultimately providing a powerful benchmark for traffic analysis across multiple datasets and tasks.\
Foundational models like large-scale Transformers (e.g., BERT, GPT) have revolutionized the field of natural language processing (NLP) by learning robust, context-rich representations of sequential data (i.e., sentences and paragraphs). These models excel at tasks such as text generation, language translation, and context-based understanding due to their ability to capture both local and global dependencies between tokens.\
Network traffic, like language, is also sequential in nature, consisting of packets or flows that carry information across multiple contexts, such as protocols, headers, payloads, and other network-specific metadata. In the same way that foundational models tokenize language into discrete units (tokens) for efficient learning and processing, network traffic can be tokenized and encoded into a sequence of meaningful representations. This parallelism opens up the potential for foundational models to not only analyze but also generate network traffic, mirroring their success in tasks like text generation.

## Recommended literature:

- Zhao, Ruijie, et al. “Yet another traffic classifier: A masked autoencoder based traffic transformer with multi-level flow representation.” Proceedings of the AAAI Conference on Artificial Intelligence. Vol. 37. No. 4. 2023.
- Lin, Xinjie, et al. “Et-bert: A contextualized datagram representation with pre-training transformers for encrypted traffic classification.” Proceedings of the ACM Web Conference 2022. 2022.
- Wu, Duo, et al. “NetLLM: Adapting large language models for networking.” Proceedings of the ACM SIGCOMM 2024 Conference. 2024.
Kholgh, Danial Khosh, and Panos Kostakos. “PAC-GPT: A novel approach to generating synthetic network traffic with GPT-3.” IEEE Access (2023).
Wang, Qineng, et al. “Lens: A Foundation Model for Network Traffic.” arXiv preprint arXiv:2402.03646 (2024).
