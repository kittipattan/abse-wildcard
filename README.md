# abse-wildcard
Secure and Efficient Multi-Keyword Wildcard Attribute-Based Searchable Encryption for IoT-EHR Systems project

## Setup: Ubuntu

### Install required packages

```bash
sudo apt update
sudo apt install git tree
sudo apt install zstd gcc build-essential
sudo apt install  flex bison python3-dev libssl-dev libgmp-dev
```

Also clone this repo

### Python environment setup

#### Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

#### Create virltual environment

```bash
# run in your project directory
uv python install
uv venv
source .venv/bin/activate
```

> [!] Activate the environment before running command below

#### Install Python packages

```bash
uv pip install -r requirement.txt
```

### Install PBC 0.5.14

```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xf pbc-0.5.14.tar.gz
cd pbc-0.5.14
./configure && make && sudo make install
sudo ldconfig
```

### Install Charm

```bash
git clone https://github.com/JHUISI/charm.git
cd charm
./configure.sh && make && sudo make install
```