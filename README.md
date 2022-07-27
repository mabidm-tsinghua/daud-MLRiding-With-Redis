# mlridin

> Tested for Python version 3.8.10.


## Installing Redis on the base OS

```sh
sudo apt-get install redis-server
```
 
### Checking Port Number and status of Radis Server

#### Opening the Redis CLI

```sh
redis-cli
```

> It also shows the port on which your REDIS server is running on.

#### Checking the redis CLI connection with server

```sh
ping
```

> PONG

If you get back the response PONG it's mean your connection is alive.

#### Exiting the CLI

```sh
QUIT
```

## Creating Virtualenv
```sh
python3 -m virtualenv venv
```

## Activating Virtualenv
```sh
source venv/bin/activate
```

## Installing dependencies

```sh
pip install -r requirements.txt
```

> It is recommended to first start MLRidin Sniffer process than start MLridinML process.

## Starting MLRidin Sniffer

```sh
cd MLRidinSniffer
```


### Usage
```sh
usage: mlridin [-h] (-i INPUT_INTERFACE | -f INPUT_FILE) [-c] [--output-file OUTPUT]

A Machine Learning based Real-time Intrusion Detection System in Network

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_INTERFACE, --interface INPUT_INTERFACE
                        This interface will be used to capture traffic in order to convert it into
                        the flow.
  -f INPUT_FILE, --file INPUT_FILE
                        This file will be converted to the flow.
  -c, --csv, --flow     The output will be store in the form of csv in output file.
  --output-file OUTPUT  default: flow.csv, The file output will be written to.
```

### Checking PCAP file
```sh
python main.py --file ../hulk.pcap -c
```

> By default, the above command will store the generated flows in the MLRidinSniffer/flow.csv file.

### Montoring interface in real time
```sh
sudo su
source venv/bin/activate
python main.py -i <interface_name> -c
```


> In order to find the interface_name, you can use `ip a` command and replace the placeholder <interface_name> with your actual interface name for instance *ens33*.
> Root privilege is require to fetch traffic from NIC in real-time.

## Starting MLRidinML module


```sh
cd MLRidinML
python main.py
```

> Make sure that the Models file exist in the directory MLRidinML/models/.
