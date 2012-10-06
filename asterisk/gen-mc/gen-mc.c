/*
An attempt to re-invent the Sipura|Linksys's "gen_mc" utility

09aug2006, v0.91
 - now reads public modulus into rsa->n from -p filename;
 - the default hash is "sha1";
11aug2006, v0.92
 - properly padding the hash before the RSA encryption;
12aug2006, v0.93
 - base64 encoding introduced;
13aug2006, v0.93a
 - base64-encoded files are single-lined: BIO_FLAGS_BASE64_NO_NL;
14aug2006, v0.94a
 - read the CA's key-pair from a regular *.PEM file;
 - read the password-protected CA's *.PEM file;
 - clear all the sensitive data out on exit;
25aug2006, v0.95
 - light cleanup (SSL_CTX not needed, excessive headers removed);
23nov2006, v0.96
 - get it to build on linux
 - add command line switches to gather user info and validate
 - build user info to sign in memory instead of from file
 - make sure all in|out files can be specified on command line
 - all errors|debug info to stderr, more error checking
 - display MC and PK to stdout in Linksys|Sipura admin manual format
 - add some help info
28nov2006, v0.97
 - checking for the CAkey size, should be exactly 1024 bits
06dec2006, v0.98
 - add -E option as the "expiry interval", i.e. days from "now"
 - add -m option to have -E interval expire at midnight
 - change default expiry date to Jan 2038 (posix long date rollover)
 - check expiry date to make sure it isn't in the past
 - add -v option to display user info and MC expiry date to stdout

To do:
 - check possible getopt() differences on different platforms
*/

#ifdef linux /* Linux */
  #include <unistd.h>
  #include <stdio.h>
  #include <fcntl.h>
#else /* QNX4, etc */
  #include <unix.h>
#endif
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <time.h>

/* prototypes */
void show_cert_info( char *cert_filename, char *userpk_filename );
void show_user_info( char *display_name, char *user_id, char *expiry_date,
		struct tm *expiry_tm );
int  set_expiry_date (int days_from_now, char *expiry_field,
		struct tm *expiry_tm, time_t *expiry_t, unsigned char midnight);
void make_date_string( char *date_string, struct tm *date_tm );
void make_date_field( char *date_field, struct tm *date_tm );
void test_dates( void );


/****
 main--
 ****/

int main( int argc, char **argv )
{
	RSA *ca_rsa, *user_rsa;
	BIO *b64, *mc_file, *user_pkey_file;
	EVP_MD_CTX mdctx;
	EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, len;
	int i, c, fd;
	FILE *fp;
	struct tm expiry_tm;
	time_t expiry_t;
	char minicert_filename[80], ca_keys_filename[80], user_pk_filename[80];
	char display_name[80], user_id[80], expiry_date[80], expiry_days[80];
	char date_field[16];
	char md_algo[16];
	unsigned char mess[2048];
	int mess_len;
	unsigned char quiet, verbose, midnight;
	unsigned char expiry_flag_count = 0;;
	unsigned char usable_key;
	unsigned char m[2048];
	unsigned int m_len;
	unsigned char sigret[2048];
	unsigned int siglen=0;
	unsigned char ca_pb_m[2048];
	int ca_pb_m_len;
	unsigned char u_pb_m[2048], u_pr_e[2048];
	int u_pb_m_len, u_pr_e_len;
	char *help =
		"\n"
		"Usage: gen-mc -k <ca_key file> -d <display_name> -u <user_id> [other options]\n"
		"Required:\n"
		"  -k <ca_key_file>  - A file with the CA's 1024-bit RSA key in PEM format\n"
		"                      To make one use \"openssl genrsa -out cakey.pem 1024\"\n"
		"  -d <display_name> - The user's display name, maximum 32 characters\n"
		"  -u <user_id>      - The user's user id, maximum 16 characters\n"
		"Optional:\n"
		"  -e <expiry_date>  - The MiniCert expiry date in HHMMSSMMDDYY format, 12 chars\n"
		"                      It defaults to 000000010138, midnight, Jan 1, 2038\n"
		"                      Excludes the use of -E\n"
		"  -E <expiry_days>  - The MiniCert expiry date in days from today, eg. 31, 365\n"
		"                      Excludes the use of -e\n"
		"  -o <minicert_file>- The file to write the MiniCert file in base64 format\n"
		"                      It defaults to mini_cert.b64\n"
		"  -p <userpk_file>  - The file to write the user's private key in base64 format\n"
		"                      It defaults to user_pk.b64\n"
		"  -m, --midnight    - When used with -E the MiniCert expires at midnight\n"
		"  -q. --quiet       - Don't write MiniCert and user's private key to stdout\n"
		"  -v. --verbose     - Write user name, id, and MiniCert expiry date to stdout\n"
		"  -h, --help        - Displays this help\n"
		"Examples:\n"
		"  gen-mc -k cakey.pem -d \"My Name\" -u 1234567 -e 000000010138\n"
		"  gen-mc -k cakey.pem -d \"My Name\" -u 1234567 -E 365 -m\n"
		"Notes:\n"
		"  This tool attempts to mimic the Linksys|Sipura gen_mc utility.\n"
		"  Use the same <ca_key_file> for all users who will use sRTP together.\n"
		"\n";

	/* command line defaults */
	strcpy( minicert_filename, "mini_cert.b64" );
	strcpy( user_pk_filename, "user_pk.b64" );
	strcpy( display_name, "" );
	strcpy( user_id, "" );
	strcpy( expiry_date, "000000010138" ); /* default - midnight, Jan 1, 2038 */
	strcpy( expiry_days, "" );
	quiet = 0;
	verbose = 0;
	midnight= 0;

	#ifdef TESTDATES
	/* test dates only and exit */
	test_dates();
	exit( EXIT_SUCCESS );
	#endif

	/* bail out if user didn't specify anything */
	if( argc <= 1 )
	{
		fprintf( stderr, help );
		exit( EXIT_FAILURE );
	}

	/* handle these options first (getopt() diffs on various platforms) */
	for ( i = 1; i < argc; ++ i )
	{
		if ( !strcmp( argv[i], "-h" ) || !strcmp( argv[i], "--help" ) )
		{
			fprintf( stderr, help );
			exit( EXIT_FAILURE );
		}
		else if ( !strcmp( argv[i], "-q" ) || !strcmp( argv[i], "--quiet" ) )
			quiet = 1;
		else if ( !strcmp( argv[i], "-v" ) || !strcmp( argv[i], "--verbose" ) )
			verbose = 1;
		else if ( !strcmp( argv[i], "-m" ) || !strcmp( argv[i], "--midnight" ) )
			midnight = 1;
	}

	/* grab all the command line args that have values */
	while( -1 != ( c = getopt( argc, argv, "-qvmhk:o:d:u:e:E:p:" ) ) )
	{
		switch( c )
		{
			/* ignore -,q,v,m,h already handled */
			/* the '-' check looks for missing value mis-interpreted as an opt */
			case 'k': /* filename containing user-supplied CA private exponent */
				if ('-' == optarg[0]) { fprintf( stderr, help ); exit( EXIT_FAILURE ); }
				strcpy( ca_keys_filename, optarg );
				break;
			case 'o': /* filename for writing the minicert */
				if ('-' == optarg[0]) { fprintf( stderr, help ); exit( EXIT_FAILURE ); }
				strcpy( minicert_filename, optarg );
				break;
			case 'p': /* filename for writing user's private key */
				if ('-' == optarg[0]) { fprintf( stderr, help ); exit( EXIT_FAILURE ); }
				strcpy( user_pk_filename, optarg );
				break;
			case 'd': /* user's display name */
				if ('-' == optarg[0]) { fprintf( stderr, help ); exit( EXIT_FAILURE ); }
				strcpy( display_name, optarg );
				break;
			case 'u': /* user's id */
				if ('-' == optarg[0]) { fprintf( stderr, help ); exit( EXIT_FAILURE ); }
				strcpy( user_id, optarg );
				break;
			case 'e': /* expiry date */
				if ('-' == optarg[0]) { fprintf( stderr, help ); exit( EXIT_FAILURE ); }
				strcpy( expiry_date, optarg );
				expiry_flag_count++;
				break;
			case 'E': /* expiry days */
				if ('-' == optarg[0]) { fprintf( stderr, help ); exit( EXIT_FAILURE ); }
				strcpy( expiry_days, optarg );
				expiry_flag_count++;
				break;
		}
	}

	/* Validate the user parameters */

	/* zero the mess out first */
	memset( mess, 0, sizeof( mess ) );

	/* check the display name */
	len = strlen( display_name );
	if ( len < 1 )
	{
		fprintf(stderr, "Error: display name is missing, use -d.\n");
		exit( EXIT_FAILURE );
	}
	if ( len > 32)
	{
		fprintf(stderr, "Error: display name can't be more than 32 characters.\n");
		exit( EXIT_FAILURE );
	}
	memcpy( mess, display_name, len ); /* display name looks ok */

	/* check the user id */
	len = strlen( user_id );
	if ( len < 1 )
	{
		fprintf(stderr, "Error: user id is missing, use -u.\n");
		exit( EXIT_FAILURE );
	}
	if ( len > 16 )
	{
		fprintf(stderr, "Error: user id can't be more than 16 characters.\n");
		exit( EXIT_FAILURE );
	}
	memcpy( mess+32, user_id, len ); /* user id looks ok */


	/* check the expiry date */

	/* bail if the user picked more than one CA expiry option */
	if ( expiry_flag_count > 1 )
	{
		fprintf(stderr, "Error: more than one expiry option specified.\n");
		exit( EXIT_FAILURE );
	}

	/* check to see if we should be using expiry days instead of full date */
	len = strlen( expiry_days );
	if (len > 0)
	{
		/* user specified expiry in days */
		i = atoi( expiry_days );
		if ( i < 1 )
		{
			fprintf(stderr, "Error: expiry days must be at least 1.\n");
			exit( EXIT_FAILURE );
		}
		if ( !set_expiry_date( i, expiry_date, &expiry_tm, &expiry_t, midnight ) )
		{
			fprintf( stderr, "Error: expiry date is out of range.\n" );
			exit( EXIT_FAILURE );
		}
	}
	else
	{
		/* user specified an complete expiry date */
		len = strlen( expiry_date );
		if ( len < 1 )
		{
			fprintf(stderr, "Error: expiry date is missing, use -e.\n");
			exit( EXIT_FAILURE );
		}
		if ( len != 12 )
		{
			fprintf(stderr, "Error: expiry date must be 12 characters.\n");
			exit( EXIT_FAILURE );
		}
		for ( i = 0; i < len; ++i )
			if ( !isdigit( expiry_date[i] ) )
			{
				fprintf(stderr, "Error: expiry date contains non-digits.\n");
				exit( EXIT_FAILURE );
			}

		/* check the individual expiry date fields */
		memset( date_field, 0, sizeof( date_field ) );
		memset( &expiry_tm, 0, sizeof( struct tm ) );
		/* hour */
		date_field[0] = expiry_date[0];
		date_field[1] = expiry_date[1];
		i = atoi ( date_field );
		expiry_tm.tm_hour = i;
		if ( i < 0 || i > 23 )
		{
			fprintf(stderr, "Error: hour in expiry date must be in 00-23 range.\n");
			exit( EXIT_FAILURE );
		}
		/* minute */
		date_field[0] = expiry_date[2];
		date_field[1] = expiry_date[3];
		i = atoi ( date_field );
		expiry_tm.tm_min = i;
		if ( i < 0 || i > 59 )
		{
			fprintf(stderr, "Error: minute in expiry date must be in 00-59 range.\n");
			exit( EXIT_FAILURE );
		}
		/* second */
		date_field[0] = expiry_date[4];
		date_field[1] = expiry_date[5];
		i = atoi ( date_field );
		expiry_tm.tm_sec = i;
		if ( i < 0 || i > 59 )
		{
			fprintf(stderr, "Error: second in expiry date must be in 00-59 range.\n");
			exit( EXIT_FAILURE );
		}
		/* month */
		date_field[0] = expiry_date[6];
		date_field[1] = expiry_date[7];
		i = atoi ( date_field );
		expiry_tm.tm_mon = i - 1; /* 0-11 */
		if ( i < 1 || i > 12 )
		{
			fprintf(stderr, "Error: month in expiry date must be in 01-12 range.\n");
			exit( EXIT_FAILURE );
		}
		/* day */
		date_field[0] = expiry_date[8];
		date_field[1] = expiry_date[9];
		i = atoi ( date_field );
		expiry_tm.tm_mday = i;
		if ( i < 1 || i > 31 )
		{
			fprintf(stderr, "Error: day in expiry date must be in 01-31 range.\n");
			exit( EXIT_FAILURE );
		}
		/* year */
		date_field[0] = expiry_date[10];
		date_field[1] = expiry_date[11];
		i = atoi ( date_field );
		expiry_tm.tm_year = i + 100; /* year since 1900 */
		/* make sure the year isn't past 2038 */
		if ( i < 0 || i > 38 )
		{
			fprintf(stderr, "Error: year in expiry date must be in 00-38 range.\n");
			exit( EXIT_FAILURE );
		}

		/* save the time_t value of the expiry date */
		expiry_t = mktime( &expiry_tm );
	}

	/* do a current time/date check here and make sure they didn't pick an expiry
	date in the past */
	if ( expiry_t < time( NULL ) )
	{
		fprintf( stderr, "Error: expiry date is in the past.\n" );
		exit( EXIT_FAILURE );
	}

	/* expiry date looks ok */
	memcpy( mess+48, expiry_date, 12 );
	mess_len = 60;

	#ifdef DEBUG
	/* dump the 60 byte user info to a file */
	if ( NULL != ( fp = fopen( "user_info.dat", "wb" ) ) )
	{
		fwrite( mess, 60, 1, fp );
		fclose( fp );
	}
	#endif

	/* Generate user's keys */

	/* try more than once if neccessary */
	#ifdef DEBUG
	fprintf( stderr, "Debug: generating user RSA key");
	#endif
	for ( usable_key = 0, i = 0; i < 16; ++i )
	{
		user_rsa = RSA_generate_key( 512, RSA_F4, NULL, NULL );
		if( NULL == user_rsa)
		{
			fprintf( stderr, "Error: RSA_generate_key() failed.\n");
			exit( EXIT_FAILURE );
		}

		c = RSA_check_key( user_rsa );
		if( !c )
		{
			RSA_free( user_rsa );
			#ifdef DEBUG
			fprintf( stderr, ".");
			#endif
		} else {
			#ifdef DEBUG
			fprintf( stderr, "\nDebug: user's RSA keys usable\n");
			fprintf( stderr, "n==%s\n", BN_bn2hex( user_rsa->n ) );
			fprintf( stderr, "e==%s\n", BN_bn2dec( user_rsa->e ) );
			fprintf( stderr, "d==%s\n", BN_bn2hex( user_rsa->d ) );
			#endif
			usable_key = 1;
			break;
		}
	}

	/* make sure we got one */
	if ( !usable_key )
	{
		fprintf( stderr, "Error: couldn't generate a usable user key.\n");
		exit( EXIT_FAILURE );
	}

	memset( u_pr_e,  0, sizeof( u_pr_e ) );
	u_pb_m_len = BN_bn2bin( user_rsa->n, u_pb_m ); /* public modulus   */
	memcpy( mess+mess_len, u_pb_m, u_pb_m_len );
	mess_len += u_pb_m_len;
	u_pr_e_len = BN_bn2bin( user_rsa->d, u_pr_e ); /* private exponent */

	/* read CA's keys from a *.PEM file, create an RSA object */
	fp = fopen( ca_keys_filename, "rb" );
	if( NULL == fp )
	{
		memset( u_pr_e,  0, sizeof( u_pr_e ) );
		RSA_free( user_rsa );
		fprintf( stderr, "Error: CA keys file %s not found.\n", ca_keys_filename );
		exit( EXIT_FAILURE );
	}

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	ca_rsa = PEM_read_RSAPrivateKey( fp, NULL, NULL, NULL );
	if( NULL == ca_rsa )
	{
		memset( u_pr_e,  0, sizeof( u_pr_e ) );
		RSA_free( user_rsa );
		fprintf( stderr, "Error: reading PEM failed\n" );
		exit( EXIT_FAILURE );
	}
	fclose( fp );

	/* check the key length here and make sure it's 1024 */
	if( 1024 != RSA_size( ca_rsa ) * 8 )
	{
		memset( u_pr_e,  0, sizeof( u_pr_e ) );
		RSA_free( user_rsa );
		RSA_free( ca_rsa );
		fprintf( stderr, "Error: wrong CA key size, should be 1024 bits\n" );
		exit( EXIT_FAILURE );
	}

	#ifdef DEBUG
	fprintf( stderr, "Debug: CApubmod==%s\n",  BN_bn2hex( ca_rsa->n ) );
	fprintf( stderr, "Debug: CApubexp==%s\n",  BN_bn2dec( ca_rsa->e ) );
	fprintf( stderr, "Debug: CAprivexp==%s\n", BN_bn2hex( ca_rsa->d ) );
	#endif

	c = RSA_check_key( ca_rsa ); /* re-check CA keys */
	if( c )
	{
		#ifdef DEBUG
		fprintf( stderr, "Debug: the CA key is valid.\n");
		#endif
	} else {
		memset( u_pr_e,  0, sizeof( u_pr_e ) );
		RSA_free( user_rsa );
		RSA_free( ca_rsa );
		fprintf( stderr, "Error: the CA key is broken.\n");
		exit( EXIT_FAILURE );
	}

	OpenSSL_add_all_digests();
	strcpy( md_algo, "sha1" );
	md = (EVP_MD *)EVP_get_digestbyname( md_algo );
	if( !md )
	{
		memset( u_pr_e,  0, sizeof( u_pr_e ) );
		RSA_free( user_rsa );
		RSA_free( ca_rsa );
		fprintf( stderr, "Error: unknown digest.\n");
		exit( EXIT_FAILURE );
	}

	EVP_MD_CTX_init( &mdctx );
	c = EVP_DigestInit_ex( &mdctx, md, NULL );
	if( !c )
	{
		memset( u_pr_e,  0, sizeof( u_pr_e ) );
		RSA_free( user_rsa );
		RSA_free( ca_rsa );
		fprintf( stderr, "Error: EVP_DigestInit_ex() failed.\n" );
		exit( EXIT_FAILURE );
	}
	c = EVP_DigestUpdate( &mdctx, mess, mess_len );
	if( !c )
	{
		memset( u_pr_e,  0, sizeof( u_pr_e ) );
		RSA_free( user_rsa );
		RSA_free( ca_rsa );
		fprintf( stderr, "Error: EVP_DigestUpdate() failed.\n" );
		exit( EXIT_FAILURE );
	}
	c = EVP_DigestFinal_ex( &mdctx, m, &m_len );
	if( !c )
	{
		memset( u_pr_e,  0, sizeof( u_pr_e ) );
		RSA_free( user_rsa );
		RSA_free( ca_rsa );
		fprintf( stderr, "Error: EVP_DigestFinal_ex() failed.\n" );
		exit( EXIT_FAILURE );
	}
	EVP_MD_CTX_cleanup( &mdctx );

	#ifdef DEBUG
	fprintf( stderr, "Debug: %s==", md_algo );
	for( c = 0; c < m_len; c++)
		fprintf( stderr, "%02x", m[c]);
	fprintf( stderr, ", m_len==%d\n", m_len);
	#endif

	siglen = RSA_private_encrypt( m_len, m, sigret, ca_rsa, RSA_PKCS1_PADDING );
	#ifdef DEBUG
	fprintf( stderr, "Debug: siglen==%d\n", siglen );
	#endif
	if( siglen )
	{
		mc_file = BIO_new_file( minicert_filename, "wb" );
		if( mc_file )
		{
			b64 = BIO_new( BIO_f_base64() );
			BIO_set_flags( b64, BIO_FLAGS_BASE64_NO_NL );
			mc_file = BIO_push( b64, mc_file );

			memcpy( mess+mess_len, sigret, siglen );
			mess_len += siglen;

			ca_pb_m_len = BN_bn2bin( ca_rsa->n, ca_pb_m ); /* CA public mod */
			memcpy( mess+mess_len, ca_pb_m, ca_pb_m_len );
			mess_len += ca_pb_m_len;

			BIO_write( mc_file, mess, mess_len );
			BIO_flush( mc_file );
			BIO_free_all( mc_file );

			user_pkey_file = BIO_new_file( user_pk_filename, "wb" );
			if( user_pkey_file )
			{
				b64 = BIO_new( BIO_f_base64() );
				BIO_set_flags( b64, BIO_FLAGS_BASE64_NO_NL );
				user_pkey_file = BIO_push( b64, user_pkey_file );

				BIO_write( user_pkey_file, u_pr_e, u_pr_e_len );
				BIO_flush( user_pkey_file );
				BIO_free_all( user_pkey_file );

				#ifdef DEBUG
				fprintf( stderr, "Debug: Done.\n" );
				#endif
			} else {
				/* creating the private key failed */
				remove( minicert_filename );/* certificate useless, delete it */
				RSA_free( user_rsa );
				RSA_free( ca_rsa );
				fprintf( stderr, "Error: creating user PK %s failed.\n", user_pk_filename );
				exit( EXIT_FAILURE );
			}
		}
	} else {
		RSA_free( user_rsa );
		RSA_free( ca_rsa );
		fprintf( stderr, "Error: RSA_private_encrypt failed.\n" );
		exit( EXIT_FAILURE );
	}

	/* wipe mem and cleanup */
	memset( u_pr_e,  0, sizeof( u_pr_e ) );
	RSA_free( user_rsa );
	RSA_free( ca_rsa );

	/* show the minicert and users private key if they want */
	if ( !quiet )
	{
		show_cert_info( minicert_filename, user_pk_filename );
	}

	/* show the user info and CA expiry if they want */
	if ( verbose )
	{
		show_user_info( display_name, user_id, expiry_date, &expiry_tm );
	}

	return( EXIT_SUCCESS );
}

/**************
 show_cert_info--
 **************/

void show_cert_info (char *cert_filename, char *userpk_filename)
{
	FILE *fp;
	unsigned char buff[2048];

	/* this format is what the example in the Sipura admin manual prints out */

	/* print out the MC */
	memset ( buff, 0, sizeof( buff ) );
	if ( NULL != ( fp = fopen( cert_filename, "r" ) ) )
	{
		fread( buff, 2048, 1, fp );
		fclose( fp );
	}
	else return;
	fprintf( stdout, "\n<Mini Certificate>\n%s\n", buff);

	/* print out the user PK */
	memset ( buff, 0, sizeof( buff ) );
	if ( NULL != ( fp = fopen( userpk_filename, "r" ) ) )
	{
		fread( buff, 2048, 1, fp );
		fclose( fp );
	}
	else return;
	fprintf( stdout, "\n<SRTP Private Key>\n%s\n\n", buff);

	return;
}

/**************
 show_user_info--
 **************/

void show_user_info( char *display_name, char *user_id, char *expiry_date,
	   struct tm *expiry_tm )
{
	char nice_time_str[80];
	make_date_string( nice_time_str, expiry_tm);
	fprintf( stdout, "<Encoded User Info>\n" );
	fprintf( stdout, "User display name..: %s\n", display_name );
	fprintf( stdout, "User id............: %s\n", user_id );
	fprintf( stdout, "Expiry date........: %s\n\n", expiry_date );
	fprintf( stdout, "This certificate expires on %s\n\n", nice_time_str );
	return;
}

/***************
 set_expiry_date--
 ***************/

int set_expiry_date (int days_from_now, char *expiry_field,
		struct tm *expiry_tm, time_t *expiry_t, unsigned char midnight)
{
	time_t now, expire_time;
	struct tm *local_expire_time;
	char nice_time_str[80];

	/* get the current time */
	now = time( NULL );

	/* Note: 12000 is just an arbitrary value that will always be past 2038.
	   And if the user specifies something in the 40000+ range the
	   following long int date calculation will actually roll over into
	   a value in the early 1900s, so prevent this.
	 */
	if ( days_from_now > 12000 )
	{
		return 0;
	}

	/* calculate expiry time */
	/* posix time_t's are calulated as (long int) seconds past the 1970 epoch */
	*expiry_t = now + (time_t)((long)days_from_now * 24 * 60 * 60);

	/* watchout for date rollover after Jan 18 2038 */
	if ( *expiry_t < 0 )
	{
		return 0;
	}

	/* Note: the conversion to future localtime() will take daylight savings
	   time into account -- if applicable. That means (in some places
	   in North America for instance) a certificate generated in January,
	   set to expire in June of the same or some following year will
	   gain an hour, and vice versa. Not a real problem, but it may
	   cause some confusion when for example a certificate generated
	   at 11:30pm in January expires at 12:30am on a day in June -- one
	   day of the month later than the user expected.
	 */

	/* convert expiry time to local time */
	local_expire_time = localtime( expiry_t );

	/* clone local_expire_time since it points to C runtime mem and
	   since we may need to change it if the user wants midnight.
	 */
	memcpy( expiry_tm, local_expire_time, sizeof( struct tm ) );

	/* override time values if midnight requested */
	if (midnight)
	{
		expiry_tm->tm_hour = 0;
		expiry_tm->tm_min  = 0;
		expiry_tm->tm_sec  = 0;
	}

	/* make the expiry date field for the MC */
	make_date_field( expiry_field, expiry_tm);

	/* no problems */
	return 1;
}

/****************
 make_date_string--
 ****************/

void make_date_string (char *date_str, struct tm *date_tm)
{
	/* normally one would use strftime() to do this but in some cases
	   we filled in the struct tm ouselves so it might be incomplete.
	 */
	char *month[] =
		{ "Jan","Feb","Mar","Apr","May","Jun",
		"Jul","Aug","Sep","Oct","Nov","Dec" };
	/* month day year hour min secs */
	sprintf ( date_str, "%s %02d %04d, %02d:%02d:%02d",
		month[date_tm->tm_mon],
		date_tm->tm_mday,
		date_tm->tm_year + 1900,
		date_tm->tm_hour,
		date_tm->tm_min,
		date_tm->tm_sec );
	return;
}

/***************
 make_date_field--
 ***************/

void make_date_field (char *date_field, struct tm *date_tm)
{
	/* HHMMSSMMDDYY */
	sprintf ( date_field, "%02d%02d%02d%02d%02d%02d",
		date_tm->tm_hour,
		date_tm->tm_min,
		date_tm->tm_sec,
		date_tm->tm_mon + 1,
		date_tm->tm_mday,
		date_tm->tm_year - 100 );
	return;
}

#ifdef TESTDATES
/**********
 test_dates--
 **********/

void test_dates ()
{
	int i;
	char expiry_field[80];
	char date_string[80];
	time_t expiry_t;
	struct tm expiry_tm;
	unsigned char midnight = 0; /* set to 1 to test midnight */
	for ( i = 1; i < 12000; ++i )
	{
		if ( !set_expiry_date( i, expiry_field, &expiry_tm, &expiry_t, midnight ) )
		{
			printf("Done.");
			break;
		}
		make_date_string( date_string, &expiry_tm);
		printf( "set_expiry_date: %d days %s (%s)\n", i, expiry_field, date_string);
	}
	return;
}
#endif
