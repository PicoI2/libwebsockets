/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "private-libwebsockets.h"

#define LWS_CPYAPP(ptr, str) { strcpy(ptr, str); ptr += strlen(str); }
#define LWS_CPYAPP_TOKEN(ptr, tok) { strcpy(p,  lws_hdr_simple_ptr(wsi, tok)); \
		p += lws_hdr_total_length(wsi, tok); }

#ifndef LWS_NO_EXTENSIONS
static int
lws_extension_server_handshake(struct lws *wsi, char **p, int budget)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	char ext_name[64], *args, *end = (*p) + budget - 1;
	const struct lws_ext_options *opts, *po;
	const struct lws_extension *ext;
	struct lws_ext_option_arg oa;
	int n, m, more = 1;
	int ext_count = 0;
	char ignore;
	char *c;

	/*
	 * Figure out which extensions the client has that we want to
	 * enable on this connection, and give him back the list
	 */
	if (!lws_hdr_total_length(wsi, WSI_TOKEN_EXTENSIONS))
		return 0;

	/*
	 * break down the list of client extensions
	 * and go through them
	 */

	if (lws_hdr_copy(wsi, (char *)pt->serv_buf, context->pt_serv_buf_size,
			 WSI_TOKEN_EXTENSIONS) < 0)
		return 1;

	c = (char *)pt->serv_buf;
	lwsl_parser("WSI_TOKEN_EXTENSIONS = '%s'\n", c);
	wsi->count_act_ext = 0;
	ignore = 0;
	n = 0;
	args = NULL;

	/*
	 * We may get a simple request
	 *
	 * Sec-WebSocket-Extensions: permessage-deflate
	 *
	 * or an elaborated one with requested options
	 *
	 * Sec-WebSocket-Extensions: permessage-deflate; \
	 *			     server_no_context_takeover; \
	 *			     client_no_context_takeover
	 */

	while (more) {

		if (*c && (*c != ',' && *c != '\t')) {
			if (*c == ';') {
				ignore = 1;
				args = c + 1;
			}
			if (ignore || *c == ' ') {
				c++;
				continue;
			}
			ext_name[n] = *c++;
			if (n < sizeof(ext_name) - 1)
				n++;
			continue;
		}
		ext_name[n] = '\0';

		ignore = 0;
		if (!*c)
			more = 0;
		else {
			c++;
			if (!n)
				continue;
		}

		while (args && *args && *args == ' ')
			args++;

		/* check a client's extension against our support */

		ext = wsi->vhost->extensions;

		while (ext && ext->callback) {

			if (strcmp(ext_name, ext->name)) {
				ext++;
				continue;
			}

			/*
			 * oh, we do support this one he asked for... but let's
			 * confirm he only gave it once
			 */
			for (m = 0; m < wsi->count_act_ext; m++)
				if (wsi->active_extensions[m] == ext) {
					lwsl_info("extension mentioned twice\n");
					return 1; /* shenanigans */
				}

			/*
			 * ask user code if it's OK to apply it on this
			 * particular connection + protocol
			 */
			m = (wsi->protocol->callback)(wsi,
				LWS_CALLBACK_CONFIRM_EXTENSION_OKAY,
				wsi->user_space, ext_name, 0);

			/*
			 * zero return from callback means go ahead and allow
			 * the extension, it's what we get if the callback is
			 * unhandled
			 */
			if (m) {
				ext++;
				continue;
			}

			/* apply it */

			ext_count++;

			/* instantiate the extension on this conn */

			wsi->active_extensions[wsi->count_act_ext] = ext;

			/* allow him to construct his context */

			if (ext->callback(lws_get_context(wsi), ext, wsi,
					  LWS_EXT_CB_CONSTRUCT,
					  (void *)&wsi->act_ext_user[
					                    wsi->count_act_ext],
					  (void *)&opts, 0)) {
				lwsl_notice("ext %s failed construction\n",
					    ext_name);
				ext_count--;
				ext++;

				continue;
			}

			if (ext_count > 1)
				*(*p)++ = ',';
			else
				LWS_CPYAPP(*p,
					  "\x0d\x0aSec-WebSocket-Extensions: ");
			*p += lws_snprintf(*p, (end - *p), "%s", ext_name);

			/*
			 *  go through the options trying to apply the
			 * recognized ones
			 */

			lwsl_debug("ext args %s", args);

			while (args && *args && *args != ',') {
				while (*args == ' ')
					args++;
				po = opts;
				while (po->name) {
					lwsl_debug("'%s' '%s'\n", po->name, args);
					/* only support arg-less options... */
					if (po->type == EXTARG_NONE &&
					    !strncmp(args, po->name,
							    strlen(po->name))) {
						oa.option_name = NULL;
						oa.option_index = po - opts;
						oa.start = NULL;
						lwsl_debug("setting %s\n", po->name);
						if (!ext->callback(
								lws_get_context(wsi), ext, wsi,
								  LWS_EXT_CB_OPTION_SET,
								  wsi->act_ext_user[
								         wsi->count_act_ext],
								  &oa, (end - *p))) {

							*p += lws_snprintf(*p, (end - *p), "; %s", po->name);
							lwsl_debug("adding option %s\n", po->name);
						}
					}
					po++;
				}
				while (*args && *args != ',' && *args != ';')
					args++;
			}

			wsi->count_act_ext++;
			lwsl_parser("count_act_ext <- %d\n",
				    wsi->count_act_ext);

			ext++;
		}

		n = 0;
		args = NULL;
	}

	return 0;
}
#endif

static int
interpret_key(const char *key, unsigned long *result)
{
	char digits[20];
	int digit_pos = 0;
	const char *p = key;
	unsigned int spaces = 0;
	unsigned long acc = 0;
	int rem = 0;

	while (*p) {
		if (!isdigit(*p)) {
			p++;
			continue;
		}
		if (digit_pos == sizeof(digits) - 1)
			return -1;
		digits[digit_pos++] = *p++;
	}
	digits[digit_pos] = '\0';
	if (!digit_pos)
		return -2;

	while (*key) {
		if (*key == ' ')
			spaces++;
		key++;
	}

	if (!spaces)
		return -3;

	p = &digits[0];
	while (*p) {
		rem = (rem * 10) + ((*p++) - '0');
		acc = (acc * 10) + (rem / spaces);
		rem -= (rem / spaces) * spaces;
	}

	if (rem) {
		lwsl_warn("nonzero handshake remainder\n");
		return -1;
	}

	*result = acc;

	return 0;
}

// Repris d'un ancienne version de la librairie, puis modifié pour être compatible avec la version draft76 des websockets (aka hixie76)
// Détail : https://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76
int handshake_00(struct lws_context *context, struct lws *wsi)
{
	unsigned long key1, key2;
	unsigned char sum[16];
	char *response;
	char *p;
	int n;

   /* Confirm we have all the necessary pieces */

	if (!lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN) ||
		!lws_hdr_total_length(wsi, WSI_TOKEN_HOST) ||
		!lws_hdr_total_length(wsi, WSI_TOKEN_CHALLENGE) ||
		!lws_hdr_total_length(wsi, WSI_TOKEN_KEY1) ||
		!lws_hdr_total_length(wsi, WSI_TOKEN_KEY2))
		/* completed header processing, but missing some bits */
		goto bail;

	/* allocate the per-connection user memory (if any) */
	if (wsi->protocol->per_session_data_size &&
					  !lws_ensure_user_space(wsi))
		goto bail;

	/* create the response packet */

	/* make a buffer big enough for everything */

	response = (char *)malloc(256 +
		lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE) +
		lws_hdr_total_length(wsi, WSI_TOKEN_CONNECTION) +
		lws_hdr_total_length(wsi, WSI_TOKEN_HOST) +
		lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN) +
		lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI) +
		lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL));
		
	if (!response) {
		lwsl_err("Out of memory for response buffer\n");
		goto bail;
	}

	p = response;
	LWS_CPYAPP(p, "HTTP/1.1 101 WebSocket Protocol Handshake\x0d\x0a"
		      "Upgrade: WebSocket\x0d\x0a"
		      "Connection: Upgrade\x0d\x0a"
		      "Sec-WebSocket-Origin: ");
	strcpy(p, lws_hdr_simple_ptr(wsi, WSI_TOKEN_ORIGIN));
	p += lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN);
#ifdef LWS_OPENSSL_SUPPORT
	if (wsi->ssl) {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Location: wss://");
	} else {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Location: ws://");
	}
#else
	LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Location: ws://");
#endif

	LWS_CPYAPP_TOKEN(p, WSI_TOKEN_HOST);
	LWS_CPYAPP_TOKEN(p, WSI_TOKEN_GET_URI);

	if (lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL)) {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Protocol: ");
		LWS_CPYAPP_TOKEN(p, WSI_TOKEN_PROTOCOL);
	}

	LWS_CPYAPP(p, "\x0d\x0a\x0d\x0a");

	/* convert the two keys into 32-bit integers */
	if (interpret_key(lws_hdr_simple_ptr(wsi, WSI_TOKEN_KEY1), &key1))
		goto bail;
	if (interpret_key(lws_hdr_simple_ptr(wsi, WSI_TOKEN_KEY2), &key2))
		goto bail;

	/* lay them out in network byte order (MSB first */

	sum[0] = (unsigned char)(key1 >> 24);
	sum[1] = (unsigned char)(key1 >> 16);
	sum[2] = (unsigned char)(key1 >> 8);
	sum[3] = (unsigned char)(key1);
	sum[4] = (unsigned char)(key2 >> 24);
	sum[5] = (unsigned char)(key2 >> 16);
	sum[6] = (unsigned char)(key2 >> 8);
	sum[7] = (unsigned char)(key2);

	/* follow them with the challenge token we were sent */
	memcpy(&sum[8], lws_hdr_simple_ptr(wsi, WSI_TOKEN_CHALLENGE), 8);

	/*
	 * compute the md5sum of that 16-byte series and use as our
	 * payload after our headers
	 */

	MD5(sum, 16, (unsigned char *)p);
	p += 16;

	/* it's complete: go ahead and send it */

	lwsl_parser("issuing response packet %d len\n", (int)(p - response));
#ifdef _DEBUG
	fwrite(response, 1,  p - response, stderr);
#endif
	n = lws_write(wsi, (unsigned char *)response,
					  p - response, LWS_WRITE_HTTP);
	if (n < 0) {
		lwsl_debug("handshake_00: ERROR writing to socket\n");
		goto bail;
	}

	/* alright clean up and set ourselves into established state */

	free(response);
	wsi->state = LWSS_ESTABLISHED;
	wsi->lws_rx_parse_state = LWS_RXPS_NEW;

	{
		const char * uri_ptr =
			lws_hdr_simple_ptr(wsi, WSI_TOKEN_GET_URI);
		int uri_len = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
		const struct lws_http_mount *hit =
			lws_find_mount(wsi, uri_ptr, uri_len);
		if (hit && hit->cgienv &&
		    wsi->protocol->callback(wsi, LWS_CALLBACK_HTTP_PMO,
			wsi->user_space, (void *)hit->cgienv, 0))
			return 1;
	}

	return 0;

bail:
	return -1;
}

int
handshake_0405(struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	unsigned char hash[20];
	int n, accept_len;
	char *response;
	char *p;

	if (!lws_hdr_total_length(wsi, WSI_TOKEN_HOST) ||
	    !lws_hdr_total_length(wsi, WSI_TOKEN_KEY)) {
		lwsl_parser("handshake_04 missing pieces\n");
		/* completed header processing, but missing some bits */
		goto bail;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_KEY) >= MAX_WEBSOCKET_04_KEY_LEN) {
		lwsl_warn("Client key too long %d\n", MAX_WEBSOCKET_04_KEY_LEN);
		goto bail;
	}

	/*
	 * since key length is restricted above (currently 128), cannot
	 * overflow
	 */
	n = sprintf((char *)pt->serv_buf,
		    "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
		    lws_hdr_simple_ptr(wsi, WSI_TOKEN_KEY));

	lws_SHA1(pt->serv_buf, n, hash);

	accept_len = lws_b64_encode_string((char *)hash, 20,
			(char *)pt->serv_buf, context->pt_serv_buf_size);
	if (accept_len < 0) {
		lwsl_warn("Base64 encoded hash too long\n");
		goto bail;
	}

	/* allocate the per-connection user memory (if any) */
	if (lws_ensure_user_space(wsi))
		goto bail;

	/* create the response packet */

	/* make a buffer big enough for everything */

	response = (char *)pt->serv_buf + MAX_WEBSOCKET_04_KEY_LEN + LWS_PRE;
	p = response;
	LWS_CPYAPP(p, "HTTP/1.1 101 Switching Protocols\x0d\x0a"
		      "Upgrade: WebSocket\x0d\x0a"
		      "Connection: Upgrade\x0d\x0a"
		      "Sec-WebSocket-Accept: ");
	strcpy(p, (char *)pt->serv_buf);
	p += accept_len;

	/* we can only return the protocol header if:
	 *  - one came in, and ... */
	if (lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL) &&
	    /*  - it is not an empty string */
	    wsi->protocol->name &&
	    wsi->protocol->name[0]) {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Protocol: ");
		p += lws_snprintf(p, 128, "%s", wsi->protocol->name);
	}

#ifndef LWS_NO_EXTENSIONS
	/*
	 * Figure out which extensions the client has that we want to
	 * enable on this connection, and give him back the list.
	 *
	 * Give him a limited write bugdet
	 */
	if (lws_extension_server_handshake(wsi, &p, 192))
		goto bail;
#endif

	//LWS_CPYAPP(p, "\x0d\x0a""An-unknown-header: blah");

	/* end of response packet */

	LWS_CPYAPP(p, "\x0d\x0a\x0d\x0a");

	if (!lws_any_extension_handled(wsi, LWS_EXT_CB_HANDSHAKE_REPLY_TX,
				       response, p - response)) {

		/* okay send the handshake response accepting the connection */

		lwsl_parser("issuing resp pkt %d len\n", (int)(p - response));
#if defined(DEBUG) && ! defined(LWS_WITH_ESP8266)
		fwrite(response, 1,  p - response, stderr);
#endif
		n = lws_write(wsi, (unsigned char *)response,
			      p - response, LWS_WRITE_HTTP_HEADERS);
		if (n != (p - response)) {
			lwsl_debug("handshake_0405: ERROR writing to socket\n");
			goto bail;
		}

	}

	/* alright clean up and set ourselves into established state */

	wsi->state = LWSS_ESTABLISHED;
	wsi->lws_rx_parse_state = LWS_RXPS_NEW;

	{
		const char * uri_ptr =
			lws_hdr_simple_ptr(wsi, WSI_TOKEN_GET_URI);
		int uri_len = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
		const struct lws_http_mount *hit =
			lws_find_mount(wsi, uri_ptr, uri_len);
		if (hit && hit->cgienv &&
		    wsi->protocol->callback(wsi, LWS_CALLBACK_HTTP_PMO,
			wsi->user_space, (void *)hit->cgienv, 0))
			return 1;
	}

	return 0;


bail:
	/* caller will free up his parsing allocations */
	return -1;
}

