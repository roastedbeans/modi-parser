/* Minimal config.h for ws_dissector compilation */
/* Generated for basic Android-compatible build */

#ifndef CONFIG_H
#define CONFIG_H

/* Version information - Aligned with installed Wireshark 4.4.9 */
#define VERSION "4.4.9"
#define WIRESHARK_VERSION_MAJOR 4
#define WIRESHARK_VERSION_MINOR 4
#define WIRESHARK_VERSION_MICRO 9

/* Basic defines */
#define HAVE_STDARG_H 1
#define HAVE_STRING_H 1
#define HAVE_STDLIB_H 1
#define HAVE_UNISTD_H 1
#define HAVE_STDINT_H 1

/* Platform detection */
#ifdef __ANDROID__
#define ANDROID 1
#endif

#ifdef __APPLE__
#define __APPLE__ 1
#endif

/* Basic features */
#define HAVE_GETTIMEOFDAY 1
#define HAVE_STRERROR 1
#define HAVE_STRNCASECMP 1

/* Enable required features for QMDL dissection */
#define HAVE_PLUGINS 1
#define HAVE_LIBPCAP 1
#define HAVE_LIBZ 1
#define HAVE_LIBSSL 1

/* Packet dissection features */
#define HAVE_PCAP 1
#define HAVE_WIRETAP 1

#endif /* CONFIG_H */
