/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file rlm_smtp.c
 * @brief smtp server authentication.
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/curl/base.h>

static fr_dict_t 	const 	*dict_radius; /*dictionary for radius protocol*/
fr_dict_t 		const 	*dict_freeradius;

extern fr_dict_autoload_t rlm_smtp_dict[];
fr_dict_autoload_t rlm_smtp_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_freeradius, .proto = "freeradius"},
	{ NULL }
};

static fr_dict_attr_t 	const 	*attr_auth_type;
static fr_dict_attr_t 	const 	*attr_user_password;
static fr_dict_attr_t 	const 	*attr_user_name;
static fr_dict_attr_t 	const 	*attr_smtp_sender_email;
static fr_dict_attr_t 	const 	*attr_smtp_recipients;
static fr_dict_attr_t 	const 	*attr_smtp_to;
static fr_dict_attr_t 	const 	*attr_smtp_cc;
static fr_dict_attr_t 	const 	*attr_smtp_bcc;
static fr_dict_attr_t 	const 	*attr_smtp_header;
static fr_dict_attr_t 	const 	*attr_smtp_body;
static fr_dict_attr_t 	const 	*attr_smtp_attachment_file;

extern fr_dict_attr_autoload_t rlm_smtp_dict_attr[];
fr_dict_attr_autoload_t rlm_smtp_dict_attr[] = {
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_smtp_sender_email, .name = "SMTP-Sender-Email", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_recipients, .name = "SMTP-Recipients", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_to, .name = "SMTP-TO", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_cc, .name = "SMTP-CC", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_bcc, .name = "SMTP-BCC", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_header, .name = "SMTP-Mail-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_body, .name = "SMTP-Mail-Body", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_attachment_file, .name = "SMTP-Attachments", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ NULL },
};

typedef struct {
	char const		*uri;		//!< URI of smtp server
	char const		*template_dir;	//!< The directory that contains all email attachments
	fr_time_delta_t 	timeout;	//!< Timeout for connection and server response
	fr_curl_tls_t		tls;
	char const		*name;		//!< Auth-Type value for this module instance.
	fr_dict_enum_t		*auth_type;
} rlm_smtp_t;

typedef struct {
	rlm_smtp_t const    	*inst;		//!< Instance of rlm_smtp.
	fr_curl_handle_t    	*mhandle;	//!< Thread specific multi handle.  Serves as the dispatch and coralling structure for smtp requests
} rlm_smtp_thread_t;

/*
 *	Holds the context for parsing the email elements
 */
typedef struct {
	REQUEST			*request;
	fr_curl_io_request_t	*randle;
	fr_cursor_t		cursor;
	fr_cursor_t		recipient_check_cursor;
	fr_cursor_t		body_cursor;
	fr_dbuff_t		vp_in;
	struct curl_slist	*recipients;
	struct curl_slist	*header;
	struct curl_slist 	*body_header;
	fr_time_t 		time;
	char 			time_str[60];
	char 			template_dir[60];
	fr_sbuff_uctx_talloc_t 	sbuff_ctx;
	fr_sbuff_uctx_talloc_t 	rcpt_ctx;
	fr_sbuff_t 		path_buffer;
	fr_sbuff_t 		rcpt_buffer;
	fr_sbuff_marker_t 	m;
	enum { UNLOADED,
		LOADED}		time_status ;
} fr_mail_ctx;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("uri", FR_TYPE_STRING, rlm_smtp_t, uri) },
	{ FR_CONF_OFFSET("template_directory", FR_TYPE_STRING, rlm_smtp_t, template_dir) },
	{ FR_CONF_OFFSET("timeout",FR_TYPE_TIME_DELTA, rlm_smtp_t, timeout) },
	{ FR_CONF_OFFSET("tls", FR_TYPE_SUBSECTION, rlm_smtp_t, tls), .subcs = (void const *) fr_curl_tls_config },//!<loading the tls values
	CONF_PARSER_TERMINATOR
};

/*
 *	Generates a curl_slist of recipients
 */
static int recipients_source(fr_mail_ctx *uctx)
{
	REQUEST			*request = uctx->request;
	VALUE_PAIR 		*vp;
	VALUE_PAIR 		*cmp_vp;
	int 			recipients_set = 0;

	/* Loop through all elements in attr_smtp_recipients, if they are not present in TO CC or BCC, add them */
	vp = fr_cursor_iter_by_da_init(&uctx->cursor, &uctx->request->packet->vps, attr_smtp_recipients);
	while (vp) {
		RDEBUG2("Initialiaing Recipient: %s", vp->vp_strvalue);
		for (cmp_vp = fr_cursor_iter_by_da_init(&uctx->recipient_check_cursor, &uctx->request->packet->vps, attr_smtp_to);
				cmp_vp; cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor)){
			if (strcmp(vp->vp_strvalue, cmp_vp->vp_strvalue) == 0){
				RDEBUG2("Duplicate found in \"TO\" %s", cmp_vp->vp_strvalue);
				goto next_recipient;
			}
		}
		for (cmp_vp = fr_cursor_iter_by_da_init(&uctx->recipient_check_cursor, &uctx->request->packet->vps, attr_smtp_cc);
				cmp_vp; cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor)){
			if (strcmp(vp->vp_strvalue, cmp_vp->vp_strvalue) == 0){
				RDEBUG2("Duplicate found in \"CC\" %s", cmp_vp->vp_strvalue);
				goto next_recipient;
			}
		}
		for (cmp_vp = fr_cursor_iter_by_da_init(&uctx->recipient_check_cursor, &uctx->request->packet->vps, attr_smtp_bcc);
			       	cmp_vp; cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor)){
			if (strcmp(vp->vp_strvalue, cmp_vp->vp_strvalue) == 0){
				RDEBUG2("Duplicate found in \"BCC\" %s", cmp_vp->vp_strvalue);
				goto next_recipient;
			}
		}
		uctx->recipient_check_cursor = uctx->cursor;
		for (cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor); cmp_vp;
				cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor)){
			if (strcmp(vp->vp_strvalue, cmp_vp->vp_strvalue) == 0){
				RDEBUG2("Duplicate found in \"Recipients\" %s", cmp_vp->vp_strvalue);
				goto next_recipient;
			}
		}
		recipients_set++;
		RDEBUG2("Adding Recipient: %s", vp->vp_strvalue);
		uctx->recipients = curl_slist_append(uctx->recipients, vp->vp_strvalue);
	next_recipient:
		vp = fr_cursor_next(&uctx->cursor);
	}
	/* Loop through all elements in attr_smtp_to, if they are not present in CC or BCC, add them */
	vp = fr_cursor_iter_by_da_init(&uctx->cursor, &uctx->request->packet->vps, attr_smtp_to);
	while (vp) {
		RDEBUG2("Initializing TO: %s", vp->vp_strvalue);
		for (cmp_vp = fr_cursor_iter_by_da_init(&uctx->recipient_check_cursor, &uctx->request->packet->vps, attr_smtp_cc);
			       	cmp_vp; cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor)){
			if (strcmp(vp->vp_strvalue, cmp_vp->vp_strvalue) == 0){
				RDEBUG2("Duplicate found in \"CC\" %s", cmp_vp->vp_strvalue);
				goto next_to;
			}
		}
		for (cmp_vp = fr_cursor_iter_by_da_init(&uctx->recipient_check_cursor, &uctx->request->packet->vps, attr_smtp_bcc);
			       	cmp_vp; cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor)){
			if (strcmp(vp->vp_strvalue, cmp_vp->vp_strvalue) == 0){
				RDEBUG2("Duplicate found in \"BCC\" %s", cmp_vp->vp_strvalue);
				goto next_to;
			}
		}
		uctx->recipient_check_cursor = uctx->cursor;
		for (cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor); cmp_vp;
				cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor)){
			if (strcmp(vp->vp_strvalue, cmp_vp->vp_strvalue) == 0){
				RDEBUG2("Duplicate found in \"TO\" %s", cmp_vp->vp_strvalue);
				goto next_to;
			}
		}
		recipients_set++;
		RDEBUG2("Adding Recipient: %s", vp->vp_strvalue);
		uctx->recipients = curl_slist_append(uctx->recipients, vp->vp_strvalue);
	next_to:
		vp = fr_cursor_next(&uctx->cursor);
	}
	/* Loop through all elements in attr_smtp_cc, if they are not present in BCC, add them */
	vp = fr_cursor_iter_by_da_init(&uctx->cursor, &uctx->request->packet->vps, attr_smtp_cc);
	while (vp) {
		RDEBUG2("Initializing CC: %s", vp->vp_strvalue);
		for (cmp_vp = fr_cursor_iter_by_da_init(&uctx->recipient_check_cursor, &uctx->request->packet->vps, attr_smtp_bcc);
			       	cmp_vp; cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor)){
			if (strcmp(vp->vp_strvalue, cmp_vp->vp_strvalue) == 0){
				RDEBUG2("Duplicate found in \"BCC\" %s", cmp_vp->vp_strvalue);
				goto next_cc;
			}
		}
		uctx->recipient_check_cursor = uctx->cursor;
		for (cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor); cmp_vp;
				cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor)){
			if (strcmp(vp->vp_strvalue, cmp_vp->vp_strvalue) == 0){
				RDEBUG2("Duplicate found in \"CC\" %s", cmp_vp->vp_strvalue);
				goto next_cc;
			}
		}
		recipients_set++;
		RDEBUG2("Adding Recipient: %s", vp->vp_strvalue);
		uctx->recipients = curl_slist_append(uctx->recipients, vp->vp_strvalue);
	next_cc:
		vp = fr_cursor_next(&uctx->cursor);
	}
	/* Add all the elements in bcc */
	vp = fr_cursor_iter_by_da_init(&uctx->cursor, &uctx->request->packet->vps, attr_smtp_bcc);
	while (vp) {
		RDEBUG2("Initializing BCC: %s", vp->vp_strvalue);
		uctx->recipient_check_cursor = uctx->cursor;
		for (cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor); cmp_vp;
				cmp_vp = fr_cursor_next(&uctx->recipient_check_cursor)){
			if (strcmp(vp->vp_strvalue, cmp_vp->vp_strvalue) == 0){
				RDEBUG2("Duplicate found in \"BCC\" %s", cmp_vp->vp_strvalue);
				goto next_bcc;
			}
		}
		recipients_set++;
		RDEBUG2("Adding Recipient: %s", vp->vp_strvalue);
		uctx->recipients = curl_slist_append(uctx->recipients, vp->vp_strvalue);
	next_bcc:
		vp = fr_cursor_next(&uctx->cursor);
	}
	RDEBUG2("%d recipients set", recipients_set);
	return recipients_set;
}

/*
 *	Generates a curl_slist of header elements header elements
 */
static int header_source(fr_mail_ctx *mail_ctx)
{
	fr_sbuff_t 		time_out;
	char const 		*date = "DATE:";
	char const 		*to = "TO: ";
	char const 		*cc = "CC: ";
	REQUEST			*request = mail_ctx->request;
	VALUE_PAIR 		*vp;

	/* Initialize the buffer for the recipients. Used for TO */
	fr_sbuff_init_talloc(mail_ctx, &mail_ctx->rcpt_buffer, &mail_ctx->rcpt_ctx, 256, SIZE_MAX);
	/* Add the preposition for the header element */
	fr_sbuff_in_bstrncpy(&mail_ctx->rcpt_buffer, to, strlen(to));
	/* Mark the buffer so we only re-write after the TO: component*/
	fr_sbuff_marker(&mail_ctx->m, &mail_ctx->path_buffer);
	vp = fr_cursor_iter_by_da_init(&mail_ctx->cursor, &mail_ctx->request->packet->vps, attr_smtp_to);
	while (vp) {
		fr_sbuff_set(&mail_ctx->rcpt_buffer, &mail_ctx->m);
		fr_sbuff_in_bstrncpy(&mail_ctx->rcpt_buffer, vp->vp_strvalue, vp->vp_length);
		mail_ctx->header = curl_slist_append(mail_ctx->header, mail_ctx->rcpt_buffer.buff);
		RDEBUG2("Adding Header: %s", mail_ctx->rcpt_buffer.buff);
		vp = fr_cursor_next(&mail_ctx->cursor);
	}
	talloc_free(mail_ctx->rcpt_buffer.buff);

	/* Initialize the buffer for the recipients. Used for CC */
	fr_sbuff_init_talloc(mail_ctx, &mail_ctx->rcpt_buffer, &mail_ctx->sbuff_ctx, 256, SIZE_MAX);
	/* Add the preposition for the header element */
	fr_sbuff_in_bstrncpy(&mail_ctx->rcpt_buffer, cc, strlen(cc));
	/* Mark the buffer so we only re-write after the CC: component */
	fr_sbuff_marker(&mail_ctx->m, &mail_ctx->path_buffer);
	vp = fr_cursor_iter_by_da_init(&mail_ctx->cursor, &mail_ctx->request->packet->vps, attr_smtp_cc);
	while (vp) {
		fr_sbuff_set(&mail_ctx->rcpt_buffer, &mail_ctx->m);
		fr_sbuff_in_bstrncpy(&mail_ctx->rcpt_buffer, vp->vp_strvalue, vp->vp_length);
		RDEBUG2("Adding Header: %s", mail_ctx->rcpt_buffer.buff);
		mail_ctx->header = curl_slist_append(mail_ctx->header, mail_ctx->rcpt_buffer.buff);
		vp = fr_cursor_next(&mail_ctx->cursor);
	}
	talloc_free(mail_ctx->rcpt_buffer.buff);

	/* Add all the generic header elements */
	fr_cursor_iter_by_da_init(&mail_ctx->cursor, &mail_ctx->request->packet->vps, attr_smtp_header);
	/* Loop through all of the header elements and append them to a curl slist */
	for ( vp = fr_cursor_current(&mail_ctx->cursor); vp; vp = fr_cursor_next(&mail_ctx->cursor)) {
		if (strncmp(vp->vp_strvalue, date, 5) == 0) {
			RDEBUG2("date set manually to: %s", vp->vp_strvalue);
			mail_ctx->time_status = LOADED;
		}
		RDEBUG2("Adding Header: %s", vp->vp_strvalue);
		mail_ctx->header = curl_slist_append(mail_ctx->header, vp->vp_strvalue);
	}
	/* If no header elements could be found, there is an error */
	if ( mail_ctx->header == NULL) {
		RDEBUG2("Header elements could not be added");
 		return -1;
	}
	/* If no time stamp was specified, add the time that the modules initially received the request */
	if (mail_ctx->time_status == UNLOADED){
		time_out = FR_SBUFF_OUT(mail_ctx->time_str, sizeof(mail_ctx->time_str));
		RDEBUG2("No date was provided, setting automatically");
		fr_time_strftime_local(&time_out, fr_time(), "DATE: %a, %d %b %Y %T %z, (%Z) \r\n");
		RDEBUG2("Adding Header: %s", mail_ctx->time_str);
		mail_ctx->header = curl_slist_append(mail_ctx->header, mail_ctx->time_str);
	}
	RDEBUG2("Finished generating the curl_slist for the header elements");
	return 0;
}

/*
 * Add the Body elements to the email
 */
static size_t body_source(char *ptr, size_t size, size_t nmemb, void *uctx)
{
	fr_mail_ctx 		*mail_ctx = uctx;
	fr_dbuff_t		out;
	REQUEST			*request = mail_ctx->request;
	VALUE_PAIR 		*vp;

	fr_dbuff_init(&out, (uint8_t *)ptr, (size * nmemb));  /* Wrap the output buffer so we can track our position easily */
	vp = fr_cursor_current(&mail_ctx->body_cursor);

	/* Copy the vp into the email. If it cannot all be loaded, return the amount of memory that was loaded and get called again */
	if (fr_dbuff_memcpy_in_partial(&out, &mail_ctx->vp_in, SIZE_MAX) < fr_dbuff_remaining(&mail_ctx->vp_in)) {
		RDEBUG2("%zu bytes used (partial copy)", fr_dbuff_used(&out));
		return fr_dbuff_used(&out);
	}
	/* Once this value pair is fully copied, prepare for the next element */
	vp = fr_cursor_next(&mail_ctx->body_cursor);
	if (vp) {
		fr_dbuff_init(&mail_ctx->vp_in, (uint8_t const *)vp->vp_strvalue, vp->vp_length);

	}
	RDEBUG2("%zu bytes used (full copy)", fr_dbuff_used(&out));
	return fr_dbuff_used(&out);
}

/*
 * Adds every SMTP_Attachments file to the email as a MIME part
 */
static int attachments_source(fr_mail_ctx *uctx, curl_mime *mime, rlm_smtp_t const *inst)
{
	curl_mimepart		*part;
	REQUEST			*request = uctx->request;
	VALUE_PAIR 		*vp;
	int 			attachments_set = 0;

	vp = fr_cursor_iter_by_da_init(&uctx->cursor, &uctx->request->packet->vps, attr_smtp_attachment_file);

	/* Initialize the buffer to write the file path */
	fr_sbuff_init_talloc(uctx, &uctx->path_buffer, &uctx->sbuff_ctx, talloc_array_length(inst->template_dir) + 128, SIZE_MAX);

	/* Write the initial path to the buffer */
	fr_sbuff_in_bstrcpy_buffer(&uctx->path_buffer, inst->template_dir);
	/* Make sure the template_directory path ends in a "/" */
	if (inst->template_dir[talloc_array_length(inst->template_dir)-2] != '/'){
		RDEBUG2("Adding / to end of template_dir");
		fr_sbuff_in_char(&uctx->path_buffer, "/");
	}
	/* Mark the buffer so we only re-write after the template_dir component */
	fr_sbuff_marker(&uctx->m, &uctx->path_buffer);

	/* Check for any file attachments */
	while(vp) {
		/* Move to the end of the template directory filepath */
		fr_sbuff_set(&uctx->path_buffer, &uctx->m);

		/* Check to see if the file attachment is valid, skip it if not */
		RDEBUG2("Trying to set attachment: %s", vp->vp_strvalue);
		if(vp->vp_tainted) {
			RDEBUG2("Skipping a tainted attachment");
			goto next;
		}
		if(strncmp(vp->vp_strvalue, "/", 1) == 0) {
			RDEBUG2("File attachments cannot be an absolute path");
			goto next;
		}
		if(strncmp(vp->vp_strvalue, "..", 2) == 0) {
			RDEBUG2("Cannot access values outside of template_directory");
			goto next;
		}

		/* Copy the filename into the buffer */
		fr_sbuff_in_bstrncpy(&uctx->path_buffer, vp->vp_strvalue, vp->vp_length);

		/* Add the file attachment as a mime encoded part */
		attachments_set++;
		RDEBUG2("ititializing attachment: %s", uctx->path_buffer.buff);
		part = curl_mime_addpart(mime);
		curl_mime_encoder(part, "base64");
		curl_mime_filedata(part, uctx->path_buffer.buff);
	next:
		vp = fr_cursor_next(&uctx->cursor);
	}
	RDEBUG2("Ititialized %d attachment(s)", attachments_set);
	talloc_free(uctx->path_buffer.buff);
	return attachments_set;
}

/*
 * Free the curl slists
 */
static int _free_mail_ctx(fr_mail_ctx *uctx)
{
	curl_slist_free_all(uctx->header);
	curl_slist_free_all(uctx->body_header);
	curl_slist_free_all(uctx->recipients);
	return 0;
}

/*
 * Check if the email was successfully sent, and if the certificate information was extracted
 */
static rlm_rcode_t mod_authorize_result(module_ctx_t const *mctx, REQUEST *request, void *rctx)
{
	fr_mail_ctx 			*mail_ctx = rctx;
	rlm_smtp_t const		*inst = talloc_get_type_abort_const(mctx->instance, rlm_smtp_t);
	fr_curl_io_request_t     	*randle = mail_ctx->randle;
	fr_curl_tls_t const		*tls;
	long 				curl_out;
	long				curl_out_valid;
	tls = &inst->tls;

	curl_out_valid = curl_easy_getinfo(randle->candle, CURLINFO_SSL_VERIFYRESULT, &curl_out);
	if (curl_out_valid == CURLE_OK){
		RDEBUG2("server certificate %s verified", curl_out ? "was" : "not");
	} else {
		RDEBUG2("server certificate result not found");
	}

	if (randle->result != CURLE_OK) {
		talloc_free(randle);
		return RLM_MODULE_REJECT;
	}

	if (tls->extract_cert_attrs) fr_curl_response_certinfo(request, randle);

	talloc_free(randle);
	return RLM_MODULE_OK;
}

/*
 *	Checks that there is a User-Name and User-Password field in the request
 *	As well as all of the required SMTP elements
 *	Sets the: username, password
 *		website URI
 *		timeout information
 *		TLS information
 *		Sender and recipient information
 *		Email header and body
 *		File attachments
 *
 *	Then it queues the request and yeilds until a response is given
 *	When it responds, mod_authorize_resume is called.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_smtp_t const		*inst = talloc_get_type_abort_const(mctx->instance, rlm_smtp_t);
	rlm_smtp_thread_t       	*t = talloc_get_type_abort(mctx->thread, rlm_smtp_thread_t);
	fr_curl_io_request_t     	*randle;
	fr_mail_ctx			*mail_ctx;
	curl_mime			*mime;
	curl_mime			*mime_body;
	curl_mimepart			*part;
	int 				body_elements;

	VALUE_PAIR const 		*vp, *smtp_header, *smtp_body, *sender_email, *username, *password;

	if (fr_pair_find_by_da(request->control, attr_auth_type, TAG_ANY) != NULL) {
		RDEBUG3("Auth-Type is already set.  Not setting 'Auth-Type := %s'", inst->name);
		return RLM_MODULE_NOOP;
	}
	/* Elements provided by the request */
	username = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);
	password = fr_pair_find_by_da(request->packet->vps, attr_user_password, TAG_ANY);
	smtp_header = fr_pair_find_by_da(request->packet->vps, attr_smtp_header, TAG_ANY);
	smtp_body = fr_pair_find_by_da(request->packet->vps, attr_smtp_body, TAG_ANY);
	sender_email = fr_pair_find_by_da(request->packet->vps, attr_smtp_sender_email, TAG_ANY);

	/* Make sure all of the essential email components are present and possible*/
	if(!smtp_header) {
		RDEBUG2("Attribute \"smtp-header\" is required for smtp");
		return RLM_MODULE_INVALID;
	}
	if (smtp_header->vp_length == 0) {
		RDEBUG2("\"smtp_header\" must not be empty");
		return RLM_MODULE_INVALID;
	}
	if(!smtp_body) {
		RDEBUG2("Attribute \"smtp-body\" is required for smtp");
		return RLM_MODULE_INVALID;
	}

	/* allocate the handle and set the curl options */
	randle = fr_curl_io_request_alloc(request);
	if (!randle){
		RDEBUG2("A handle could not be allocated for the request");
		return RLM_MODULE_FAIL;
	}

	/* Initialize the mail_ctx to perform the email */
	mail_ctx = talloc_zero(randle, fr_mail_ctx);
	*mail_ctx = (fr_mail_ctx) {
		.request 	= request,
		.randle 	= randle,
		.time_status 	= UNLOADED,
		.time 		= fr_time()
	};
	strcpy(mail_ctx->template_dir, inst->template_dir); /* time the request was received. Used to set DATE: if none is supplied */
	if( mail_ctx->template_dir[strlen(mail_ctx->template_dir)-1] != '/'){
		mail_ctx->template_dir[strlen(mail_ctx->template_dir)] = '/';
		RDEBUG2("Adding / to template_directory path");
	}

	/* Set the destructor function to free all of the curl_slist elements */
	talloc_set_destructor(mail_ctx, _free_mail_ctx);

	/* Set the username and pasword if they have been provided */
	if (username && username->vp_length != 0) {
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_USERNAME, username->vp_strvalue);
		RDEBUG2("Username set");
		if (password) {
			FR_CURL_REQUEST_SET_OPTION(CURLOPT_PASSWORD, password->vp_strvalue);
			RDEBUG2("Password set");
		}
	}
	/* Set the generic curl request conditions */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_URL, inst->uri);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_DEFAULT_PROTOCOL, "smtp");
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_TIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_VERBOSE, 1L);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_UPLOAD, 1L);

	/* Set the sender email */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_MAIL_FROM, sender_email->vp_strvalue);

	/* Set the recipients */
	mail_ctx->recipients = NULL; /* Prepare the recipients curl_slist to be initialized */
       	if(recipients_source(mail_ctx) <= 0) {
		RDEBUG2("At least one recipient is required to send an email");
		goto error;
	}
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_MAIL_RCPT, mail_ctx->recipients);

	/* Set the header elements */
	mail_ctx->header = NULL; /* Prepare the header curl_slist to be initialized */
       	if(header_source(mail_ctx) != 0) {
		RDEBUG2("The header slist could not be created");
		goto error;
	}
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_HTTPHEADER, mail_ctx->header);

	/* Initialize the mime structures for encoding data */
	mime = curl_mime_init(randle->candle); /* Holds the non-essential email data */
	mime_body = curl_mime_init(randle->candle); /* used to apply special conditions to the body elements */

	/* initialize the cursor by the body_source function*/
	vp = fr_cursor_iter_by_da_init(&mail_ctx->body_cursor, &mail_ctx->request->packet->vps, attr_smtp_body);
	fr_dbuff_init(&mail_ctx->vp_in, (uint8_t const *)vp->vp_strvalue, vp->vp_length);

	/* Initialize the cursor to generate the parts for every body element */
	vp = fr_cursor_iter_by_da_init(&mail_ctx->cursor, &mail_ctx->request->packet->vps, attr_smtp_body);

	/* Add a mime part to mime_body for every body element */
	body_elements = 0;
	while(vp){
		body_elements++;
		part = curl_mime_addpart(mime_body);
		curl_mime_encoder(part, "8bit");
		curl_mime_data_cb(part, vp->vp_length, body_source, NULL, NULL, mail_ctx);
		vp = fr_cursor_next(&mail_ctx->cursor);
	}
	RDEBUG2("initialized %d body element part(s)", body_elements);

	/* Add body_mime as a subpart of the mime request with a local content-disposition*/
	part = curl_mime_addpart(mime);
	curl_mime_subparts(part, mime_body);
	curl_mime_type(part, "multipart/mixed" );
	mail_ctx->body_header = curl_slist_append(NULL, "Content-Disposition: inline"); /* Initialize the body_header curl_slist */
	curl_mime_headers(part, mail_ctx->body_header, 1);

	/* Set the attachments if there are any*/
	if(attachments_source(mail_ctx, mime, inst) == 0){
		RDEBUG2("No files were attached to the email");
	}

	/* Add the mime endoced elements to the curl request */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_MIMEPOST, mime);

	/* Initialize tls if it has been set up */
	if (fr_curl_easy_tls_init(randle, &inst->tls) != 0) return RLM_MODULE_INVALID;

	if (fr_curl_io_request_enqueue(t->mhandle, request, randle)) return RLM_MODULE_INVALID;

	return unlang_module_yield(request, mod_authorize_result, NULL, mail_ctx);
error:
	return RLM_MODULE_INVALID;
}
/*
 * 	Called when the smtp server responds
 * 	It checks if the response was CURLE_OK
 * 	If it was, it tries to extract the certificate attributes
 * 	If the response was not OK, we REJECT the request
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate_resume(module_ctx_t const *mctx, REQUEST *request, void *rctx)
{
	rlm_smtp_t const		*inst = talloc_get_type_abort_const(mctx->instance, rlm_smtp_t);
	fr_curl_io_request_t     	*randle = rctx;
	fr_curl_tls_t const		*tls;
	long 				curl_out;
	long				curl_out_valid;

	tls = &inst->tls;

	curl_out_valid = curl_easy_getinfo(randle->candle, CURLINFO_SSL_VERIFYRESULT, &curl_out);
	if (curl_out_valid == CURLE_OK){
		RDEBUG2("server certificate %s verified", curl_out ? "was" : "not");
	} else {
		RDEBUG2("server certificate result not found");
	}

	if (randle->result != CURLE_OK) {
		talloc_free(randle);
		return RLM_MODULE_REJECT;
	}

	if (tls->extract_cert_attrs) fr_curl_response_certinfo(request, randle);

	talloc_free(randle);
	return RLM_MODULE_OK;
}
/*
 *	Checks that there is a User-Name and User-Password field in the request
 *	Checks that User-Password is not Blank
 *	Sets the: username, password
 *		website URI
 *		timeout information
 *		and TLS information
 *
 *	Then it queues the request and yeilds until a response is given
 *	When it responds, mod_authenticate_resume is called.
 */
static rlm_rcode_t CC_HINT(nonnull(1,2)) mod_authenticate(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_smtp_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_smtp_t);
	rlm_smtp_thread_t       *t = talloc_get_type_abort(mctx->thread, rlm_smtp_thread_t);
	VALUE_PAIR const 	*username, *password;
	fr_curl_io_request_t    *randle;

	randle = fr_curl_io_request_alloc(request);
	if (!randle){
	error:
		return RLM_MODULE_FAIL;
	}

	username = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);
	password = fr_pair_find_by_da(request->packet->vps, attr_user_password, TAG_ANY);

	/* Make sure we have a user-name and user-password, and that they are possible */
	if (!username) {
		REDEBUG("Attribute \"User-Name\" is required for authentication");
		return RLM_MODULE_INVALID;
	}
	if (username->vp_length == 0) {
		RDEBUG2("\"User-Password\" must not be empty");
		return RLM_MODULE_INVALID;
	}
	if (!password) {
		RDEBUG2("Attribute \"User-Password\" is required for authentication");
		return RLM_MODULE_INVALID;
	}

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_DEFAULT_PROTOCOL, "smtp");
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_URL, inst->uri);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_TIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_VERBOSE, 1L);

	if (fr_curl_easy_tls_init(randle, &inst->tls) != 0) return RLM_MODULE_INVALID;

	if (fr_curl_io_request_enqueue(t->mhandle, request, randle)) return RLM_MODULE_INVALID;

	return unlang_module_yield(request, mod_authenticate_resume, NULL, randle);
}


/*
 *	Initialize global curl instance
 */
static int mod_load(void)
{
	if (fr_curl_init() < 0) return -1;
	return 0;
}
/*
 *	Close global curl instance
 */
static void mod_unload(void)
{
	fr_curl_free();
}

/*
 *	Initialize a new thread with a curl instance
 */
static int mod_thread_instantiate(UNUSED CONF_SECTION const *conf, void *instance, fr_event_list_t *el, void *thread)
{
	rlm_smtp_thread_t    		*t = thread;
	fr_curl_handle_t    		*mhandle;

	t->inst = instance;

	mhandle = fr_curl_io_init(t, el, false);
	if (!mhandle) return -1;

	t->mhandle = mhandle;
	return 0;
}

/*
 *	Close the thread and free the memory
 */
static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
	rlm_smtp_thread_t    *t = thread;
	talloc_free(t->mhandle);
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_smtp;
module_t rlm_smtp = {
	.magic		        = RLM_MODULE_INIT,
	.name		        = "smtp",
	.type		        = RLM_TYPE_THREAD_SAFE,
	.inst_size	        = sizeof(rlm_smtp_t),
	.thread_inst_size   	= sizeof(rlm_smtp_thread_t),
	.config		        = module_config,
	.onload            	= mod_load,
	.unload             	= mod_unload,
	.thread_instantiate 	= mod_thread_instantiate,
	.thread_detach      	= mod_thread_detach,

	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]         = mod_authorize,
	},
};
