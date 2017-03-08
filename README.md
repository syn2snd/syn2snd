# syn2snd: port scan audibilizator and visualizer

Plays TCP SYNs and UDP packets as sound and visualizes port numbers and source addresses on a grid.

[![youtube link](https://raw.githubusercontent.com/syn2snd/syn2snd/master/syn2snd.png)](https://www.youtube.com/watch?v=QS1wooQQcp0)

## 1. Install requirements:

- libpcap: `sudo apt-get install libpcap-dev`

- libsdl2: `sudo apt-get install libsdl2-dev`

## 2. Compile:

``gcc -O3 syn2snd.c `sdl2-config --cflags --libs` -lpcap -lao -lm -lfftw3 -o syn2snd``

## 3. Enable execution as regular user:

`sudo setcap cap_net_raw,cap_net_admin=eip syn2snd`

## 4. Run

`./syn2snd`
