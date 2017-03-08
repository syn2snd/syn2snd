#include <pcap.h>
#include <stdio.h>

#include <SDL2/SDL.h>

#define __FAVOR_BSD /* to have th_dst etc. in struct tcphdr */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ao/ao.h>
#include <math.h>
#include <string.h>
#include <limits.h>
#include <fftw3.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <stdbool.h>

#define max(a,b) ((a) > (b) ? (a) : (b))
#define min(a,b) ((a) < (b) ? (a) : (b))

#define PIXELS_PER_PORT 3
#define REDRAW_PERIOD 1
#define NUM_SAMPLES 1024

#define COLOR_DECAY_FACTOR 1.0

#define SOUND_MAX_INTENSITY (255 * 10)
#define SOUND_DECAY_FACTOR (COLOR_DECAY_FACTOR * 10.0)

#define SLEEP_US 1000

unsigned int last_seen[65536];
unsigned int last_seen_addr[65536];
bool last_seen_tcp[65536];
int iteration;
int have_samples;

void audio_callback(void *data, Uint8 *stream, int len)
{
  static fftw_plan fft_plan;
  static double *in, *out;
  if(!in) {
    in  = fftw_malloc (have_samples * sizeof(double));
    out = fftw_malloc (have_samples * sizeof(double));
    fft_plan = fftw_plan_r2r_1d(have_samples, in, out, FFTW_HC2R, FFTW_BACKWARD);
  }
  int32_t *int32_t_stream = (int32_t *)stream;
  int i;
  int j;
  int step_size = 65536 / (have_samples / 4);
  int active_ports = 0;
  for(i = 0; i < have_samples / 4; i++) {
    in[i] = 0.0;
    for(j = 0; j < step_size; j++) {
      int intensity = max(0, SOUND_MAX_INTENSITY - SOUND_DECAY_FACTOR * (iteration - last_seen[i * step_size + j]));
      if(intensity)
        active_ports++;
      in[i] = max(in[i], intensity);
    }
  }
  for(; i < have_samples; i++)
    in[i] = 0.0;

  double m = 0.0;
  fftw_execute(fft_plan);

  for(i = 0; i < have_samples; i++) {
    double a = fabs(out[i]);
    if(a >= m)
      m = a;
  }

  if(m == 0.0)
    m = 1.0;
  
  for(i = 0; i < len / sizeof(int32_t); i++) {
    int32_t_stream[i] = 0.50 * INT_MAX * out[i] / ((active_ports + 1) * SOUND_MAX_INTENSITY);
  }
}

void init_audio()
{
  SDL_AudioSpec want, have;

  SDL_memset(&want, 0, sizeof(want));
  want.freq = 48000;
  want.format = AUDIO_S32SYS;
  want.channels = 1;
  want.samples = NUM_SAMPLES;
  want.callback = audio_callback;
  
  if (SDL_OpenAudio(&want, &have) < 0) {
      SDL_Log("failed to open audio: %s", SDL_GetError());
  } else {
    if (have.format != want.format) {
        SDL_Log("could not get desired audio format.");
    }
  }

  have_samples = have.samples;
  printf("have.samples: %d\n", have.samples);

  SDL_PauseAudio(0);
}

/* based on www.tcpdump.org/pcap.html and
   http://codereview.stackexchange.com/questions/118002/linux-c-port-knock-implementation */
int main(int argc, char *argv[])
{
	pcap_t *handle;
	char *dev; // for testing, use "lo";
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp[tcpflags] & tcp-syn != 0 or udp";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;

  int i;
  for(i = 0; i < 65536; i++)
    last_seen[i] = INT_MAX;

  SDL_SetHint(SDL_HINT_NO_SIGNAL_HANDLERS, "1");
  SDL_Window* window = NULL;
  window = SDL_CreateWindow
  (
      "syn2snd", SDL_WINDOWPOS_UNDEFINED,
      SDL_WINDOWPOS_UNDEFINED,
      256 * PIXELS_PER_PORT,
      256 * PIXELS_PER_PORT,
      SDL_WINDOW_SHOWN
  );

  SDL_Renderer* renderer = NULL;
  renderer =  SDL_CreateRenderer( window, -1, SDL_RENDERER_ACCELERATED);

  SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );

  SDL_RenderClear( renderer );

  SDL_Rect rect;
  rect.w = PIXELS_PER_PORT;
  rect.h = PIXELS_PER_PORT;

	init_audio();

	dev = pcap_lookupdev(errbuf);
	printf("will capture on %s\n", dev);
	if (dev == NULL) {
		printf("could not find default device: %s\n", errbuf);
		return 1;
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		printf("could not get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

  handle = pcap_create(dev, errbuf);
	if (handle == NULL) {
		printf("could not open device %s: %s\n", dev, errbuf);
		return 1;
	}

  if (pcap_set_timeout(handle, 10))
  {
    printf("could not set timeout\n");
    return 1;
  }

  if (pcap_set_buffer_size(handle, 1024 * 1024 * 100))
  {
    printf("could not set buffer size\n");
    return 1;
  }

  if (pcap_activate(handle))
  {
    printf("could not activate handle\n");
    return 1;
  }
  
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		printf("could not parse filter %s: %s\n", filter_exp,
			   pcap_geterr(handle));
		return 1;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		printf("could not install filter %s: %s\n", filter_exp,
			   pcap_geterr(handle));
		return 1;
	}

  SDL_RenderPresent(renderer);
  
  for(iteration = 0;; iteration++) {
		packet = pcap_next(handle, &header);
    
    usleep(SLEEP_US);

    if(iteration % REDRAW_PERIOD == 0)
    {
      SDL_RenderPresent(renderer);
      int i;
      for(i = 0; i < 65536; i++) {
        rect.x = ((65536 - i) % 256) * PIXELS_PER_PORT;
        rect.y = ((65536 - i) / 256) * PIXELS_PER_PORT;

        float intensity = (float)max(0, 255 - COLOR_DECAY_FACTOR * (iteration - last_seen[i])) / 255.0;
        unsigned int addr = last_seen_addr[i];
        unsigned char r = (addr >> 16) & 0xff, g = (addr >> 8) & 0xff, b = addr & 0xff;
        float norm_factor = 255.0 / max(r, max(g, b));
        
        r *= intensity * norm_factor * intensity;
        g *= intensity * norm_factor * intensity;
        b *= intensity * norm_factor * intensity;

        SDL_SetRenderDrawColor(renderer, r, g, b, 255 );
        if(last_seen_tcp[i]) {
          SDL_RenderFillRect(renderer, &rect);
        } else {
          SDL_RenderDrawPoint(renderer, rect.x + PIXELS_PER_PORT / 2, rect.y + PIXELS_PER_PORT / 2);
        }
      }
    }

		if (packet == NULL)
			continue;

		const struct ether_header *eptr = (struct ether_header *) packet;

		uint16_t et = ntohs(eptr->ether_type);

		if (et == ETHERTYPE_IP) {
			u_int size_ip;

			const struct iphdr *ip =
				(struct iphdr *) (packet + ETHER_HDR_LEN);

			size_ip = ip->ihl * 4;
			if (size_ip < 20)
				continue;

      uint16_t dport;
      if(ip->protocol == 6) {
			  const struct tcphdr *tcp =
			  	(struct tcphdr *) (packet + ETHER_HDR_LEN + size_ip);

			  if (tcp->th_off * 4 < 20)
			  	continue;

			  dport = ntohs(tcp->th_dport);
        last_seen_tcp[dport] = true;
      } else if(ip->protocol == 17) {
			  const struct udphdr *udp =
			  	(struct udphdr *) (packet + ETHER_HDR_LEN + size_ip);

        if (udp->len * 4 < 8)
          continue;

        dport = ntohs(udp->uh_dport);
        last_seen_tcp[dport] = false;
      } else {
        continue;
      }

      last_seen[dport] = iteration;
      last_seen_addr[dport] = ip->saddr;
		} else {
			printf("non-ethernet\n");
		}

	} while (1);

	pcap_close(handle);

	return 0;
}
