#include <libssh2.h>

#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <sys/select.h>

#ifndef INADDR_NONE
#define INADDR_NONE (in_addr_t)-1
#endif

#define OPT_KNOWNHOSTS	'f'
#define OPT_TIMEOUT	't'
#define OPT_PORT	'p'
#define OPT_STRICT	's'
#define OPT_VERBOSE	'v'
#define OPT_HELP	'h'
#define OPT_DEBUG	'd'
#define OPT_MESSAGE	'm'

#define OPTSTRING	"f:t:p:svhdm:"

#define	NAG_OKAY	0
#define NAG_WARN	1
#define NAG_CRIT	2
#define NAG_WTF		3

char	*known_hosts_path	= NULL;
char	*port			= "ssh";
int	timeout			= 0;
int	strict			= 0;
int	verbose			= 0;
int	debug			= 0;
char	*message		= NULL;

char	*progname		= "check_ssh";

void logmsg(char *msg, ...) {
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, msg);
	vfprintf(stderr, msg, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void nag_exit (int status, char *msg, ...) {
	va_list ap;

	printf("SSH ");
	switch (status) {
		case NAG_OKAY:
			printf("OKAY - ");
			break;
		case NAG_WARN:
			printf("WARN - ");
			break;
		case NAG_CRIT:
			printf("CRITICAL - ");
			break;
		case NAG_WTF:
			printf("UNKNOWN - ");
			break;
	}

	va_start(ap, msg);
	vprintf(msg, ap);
	va_end(ap);

	printf("\n");

	exit(status);
}

void usage (FILE *out) {
	fprintf(out, "%s: usage: %s [ -f known_hosts ] [ -p port ] [ -t timeout ] [ -sv ] host\n",
			progname, progname);
}

void process_args (int argc, char *argv[]) {
	int c;

	while (EOF != (c = getopt(argc, argv, OPTSTRING))) {
		switch (c) {
			case OPT_KNOWNHOSTS:
				known_hosts_path = strdup(optarg);
				break;

			case OPT_TIMEOUT:
				timeout = atoi(optarg);
				break;

			case OPT_PORT:
				port = optarg;
				break;

			case OPT_STRICT:
				strict = 1;
				break;

			case OPT_VERBOSE:
				verbose = 1;
				break;

			case OPT_DEBUG:
				debug = 1;
				break;

			case OPT_HELP:
				usage(stdout);
				exit(0);

			case OPT_MESSAGE:
				message = optarg;
				break;

			case '?':
				usage(stderr);
				exit(2);
		}
	}
}

struct addrinfo *get_first_address (const char *hostname) {
	struct addrinfo *res, hints;

	if (0 != getaddrinfo(hostname, port,  NULL, &res)) {
		nag_exit(NAG_WTF, "%s: hostname lookup failed", hostname);
	}

	return res;
}

int main(int argc, char *argv[])
{
	char *server_name;
	struct addrinfo *server_addr;
	int i, rc, sock = -1;
	const char *fingerprint;
	char 	*fingerprint_hex;
	const char *hostkey;
	size_t hklen;
	int hktype;
	LIBSSH2_SESSION *session;
	LIBSSH2_KNOWNHOSTS *hosts = NULL;
	struct libssh2_knownhost *store;

	process_args(argc, argv);
	argc = argc-optind;
	argv = argv + optind;

	if (!argc)
		nag_exit(NAG_WTF, "you must provide a hostname or address");

	server_name = argv[0];
	server_addr = get_first_address(server_name);

	if (0 != libssh2_init (0)) {
		nag_exit (NAG_WTF, "libssh2 initialization failed (%d)", rc);
	}

	/* Create a session instance */
	session = libssh2_session_init();
	if(!session) {
		nag_exit(NAG_WTF, "Could not initialize SSH session");
	}

	if (debug)
		libssh2_trace(session, ~0);

	/* Connect to SSH server */
	sock = socket(server_addr->ai_family, SOCK_STREAM, IPPROTO_TCP);
	if (connect(sock, server_addr->ai_addr,
				server_addr->ai_addrlen) != 0) {
		nag_exit(NAG_CRIT, "%s: connection failed", server_name);
	}

	hosts = libssh2_knownhost_init(session);

	if (known_hosts_path)
		if (0 != libssh2_knownhost_readfile(hosts,
					known_hosts_path,
					LIBSSH2_KNOWNHOST_FILE_OPENSSH))
			nag_exit(NAG_WTF,
					"Failed to read known_hosts file.");

	if (0 != (rc = libssh2_session_startup(session, sock))) {
		nag_exit(NAG_CRIT,
				"Error when starting up SSH session: %d",
				rc);
	}

	// Get host key fingerprint and convert it into a string of
	// hex digits.
	fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	fingerprint_hex = (char *)malloc(strlen(fingerprint) * 3);
	for(i = 0; i < 20; i++)
		sprintf((char *)(fingerprint_hex + (i*3)), "%02x:", (unsigned char)fingerprint[i]);
	fingerprint_hex[strlen(fingerprint_hex)-1] = '\0';

	if (verbose)
		logmsg("%s key fingerprint: %s", server_name, fingerprint_hex);

	if (NULL == (hostkey = libssh2_session_hostkey(session,
					&hklen, &hktype)))
		nag_exit(NAG_WTF, "failed to obtain host key");

	libssh2_session_disconnect(session,
			message
			? message
			: "check_ssh_key: Host key exchange completed.");

	// Check host key against known hosts cache.
	rc = libssh2_knownhost_check(hosts,
			server_name,
			hostkey, hklen, 
			LIBSSH2_KNOWNHOST_TYPE_PLAIN|LIBSSH2_KNOWNHOST_KEYENC_RAW|
			(hktype == LIBSSH2_HOSTKEY_TYPE_RSA
			 ? LIBSSH2_KNOWNHOST_KEY_SSHRSA
			 : LIBSSH2_KNOWNHOST_KEY_SSHDSS),
			&store);

	switch (rc) {
		case LIBSSH2_KNOWNHOST_CHECK_FAILURE:
			if (verbose)
				logmsg("knownhost check: failed");

			nag_exit(NAG_WTF, "knownhost check failed");
			break;
		case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
			if (verbose)
				logmsg("knownhost check: host not found");

			if (!strict && known_hosts_path) {
				if (verbose)
					logmsg("adding host %s to %s.", server_name, known_hosts_path);

				libssh2_knownhost_addc(hosts,
						server_name, "",
						hostkey, hklen,
						NULL, 0,
						LIBSSH2_KNOWNHOST_TYPE_PLAIN|LIBSSH2_KNOWNHOST_KEYENC_RAW|
						(hktype == LIBSSH2_HOSTKEY_TYPE_RSA ? LIBSSH2_KNOWNHOST_KEY_SSHRSA
						 : LIBSSH2_KNOWNHOST_KEY_SSHDSS),
						NULL);

				if (0 != libssh2_knownhost_writefile(hosts,
							known_hosts_path,
						LIBSSH2_KNOWNHOST_FILE_OPENSSH))
					nag_exit(NAG_WTF, "Failed to write known_hosts file.");

				nag_exit(NAG_OKAY, "%s: %s", server_name, fingerprint_hex);
			} else if (strict) {
				nag_exit(NAG_CRIT, "%s: host key verification failed", server_name);
			} else {
				nag_exit(NAG_WARN, "%s: host key unknown", server_name);
			}
		case LIBSSH2_KNOWNHOST_CHECK_MATCH:
			if (verbose)
				logmsg("knownhost check: matched");

			nag_exit(NAG_OKAY, "%s: %s",
					server_name,
					fingerprint_hex);
			break;
		case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
			if (verbose)
				logmsg("knownhost check: mismatch");

			nag_exit(NAG_CRIT, "%s: host key verification failed");
			break;
	}

shutdown:
	close(sock);
	libssh2_exit();

	return 0;
}

