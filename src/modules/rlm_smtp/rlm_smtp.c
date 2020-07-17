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
static fr_dict_attr_t 	const 	*attr_smtp_header;
static fr_dict_attr_t 	const 	*attr_smtp_body;
static fr_dict_attr_t 	const 	*attr_smtp_sender_email;
static fr_dict_attr_t 	const 	*attr_smtp_recipients;
static fr_dict_attr_t 	const 	*attr_smtp_attachment_file;


extern fr_dict_attr_autoload_t rlm_smtp_dict_attr[];
fr_dict_attr_autoload_t rlm_smtp_dict_attr[] = {
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_smtp_header, .name = "SMTP-Mail-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_body, .name = "SMTP-Mail-Body", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_sender_email, .name = "SMTP-Sender-Email", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_recipients, .name = "SMTP-Recipients", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smtp_attachment_file, .name = "SMTP-Attachments", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ NULL },
};

typedef struct {
	char const		*uri;		//!< URI of smtp server
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
// typedef struct mail_ctx_t;
// typedef struct mail_ctx_s {};
typedef struct {
	REQUEST			*request;
	fr_curl_io_request_t	*randle;
	fr_cursor_t		cursor;
	fr_dbuff_t		vp_in;
	fr_dbuff_t		le_in;
	struct curl_slist	*recipients;
	struct curl_slist	*header;
	fr_time_t 		time;
	size_t 			(* function_source)(char *ptr, size_t size, size_t nmemb, void *uctx);
	char 			time_str[60];
	enum { UNLOADED,
		LOADED}		time_status ;
} fr_mail_ctx;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("uri", FR_TYPE_STRING, rlm_smtp_t, uri) },
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

	fr_cursor_iter_by_da_init(&uctx->cursor, &uctx->request->packet->vps, attr_smtp_recipients);

	for ( vp = fr_cursor_current(&uctx->cursor); vp; vp = fr_cursor_next(&uctx->cursor)) {
		RDEBUG2("Adding Recipient: %s", vp->vp_strvalue);
		uctx->recipients = curl_slist_append(uctx->recipients, vp->vp_strvalue);
	}
	if ( uctx->recipients == NULL) {
		RDEBUG2("Recipients could not be found");
 		return -1;
	}
	return 0;
}
/*
 *	Generates a curl_slist of recipients
 */
static int header_slist_source(fr_mail_ctx *uctx)
{
	REQUEST			*request = uctx->request;
	VALUE_PAIR 		*vp;

	fr_cursor_iter_by_da_init(&uctx->cursor, &uctx->request->packet->vps,attr_smtp_header);
	RDEBUG2("RUNNING");

	for ( vp = fr_cursor_current(&uctx->cursor); vp; vp = fr_cursor_next(&uctx->cursor)) {
		RDEBUG2("Adding Header: %s", vp->vp_strvalue);
		uctx->header = curl_slist_append(uctx->header, vp->vp_strvalue);
	}
	if ( uctx->header == NULL) {
		RDEBUG2("Header could not be found");
 		return -1;
	}
	return 0;
}
static int attachments_source(fr_mail_ctx *uctx, curl_mime *mime)
{
	curl_mimepart		*part;
	REQUEST			*request = uctx->request;
	VALUE_PAIR 		*vp;
	int 			attachments_set = 0;
	fr_cursor_iter_by_da_init(&uctx->cursor, &uctx->request->packet->vps, attr_smtp_attachment_file);

	for ( vp = fr_cursor_current(&uctx->cursor); vp; vp = fr_cursor_next(&uctx->cursor)) {
		attachments_set++;
		RDEBUG2("Adding Attachment: %s", vp->vp_strvalue);
		part = curl_mime_addpart(mime);
		curl_mime_type(part, "multipart/alternative");
		curl_mime_filedata(part, vp->vp_strvalue);
	}
	part = curl_mime_addpart(mime);
	curl_mime_data(part, "hypothetical body line", CURL_ZERO_TERMINATED);
	part = curl_mime_addpart(mime);
	curl_mime_data(part, "hypothetical body line 2", CURL_ZERO_TERMINATED);
	RDEBUG2("%d Attachments were found", attachments_set);
	return attachments_set;
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
	static char const 	*le = "\r\n";
	RDEBUG2("inside body_source");
	fr_dbuff_init(&out, (uint8_t *)ptr, (size * nmemb));  /* Wrap the output buffer so we can track our position easily */
	RDEBUG2("dbuff initialized");
	while (true) {
		if (fr_dbuff_memcpy_in_partial(&out, &mail_ctx->vp_in, SIZE_MAX) < fr_dbuff_remaining(&mail_ctx->vp_in)) return fr_dbuff_used(&out);
		if (fr_dbuff_memcpy_in_partial(&out, &mail_ctx->le_in, SIZE_MAX) < fr_dbuff_remaining(&mail_ctx->le_in)) return fr_dbuff_used(&out);
		vp = fr_cursor_next(&mail_ctx->cursor);
		if (!vp) break;
		fr_dbuff_init(&mail_ctx->vp_in, (uint8_t const *)vp->vp_strvalue, vp->vp_length);
		fr_dbuff_init(&mail_ctx->le_in, (uint8_t const *)le, 2*sizeof(unsigned char));
	}
	return fr_dbuff_used(&out);
}
/*
 * Add the header elements to the email
 */
static size_t header_source(char *ptr, size_t size, size_t nmemb, void *uctx)
{
	fr_mail_ctx 		*mail_ctx = uctx;
	fr_dbuff_t		out;
	fr_sbuff_t 		time_out;
	REQUEST			*request = mail_ctx->request;
	VALUE_PAIR 		*vp;
	static char const 	*le = "\r\n";
	char const 		*date = "DATE:";
	fr_dbuff_init(&out, (uint8_t *)ptr, (size * nmemb));  /* Wrap the output buffer so we can track our position easily */
	RDEBUG2("dbuff initialized");
	vp = fr_cursor_current(&mail_ctx->cursor);
	while (true) {
		if (strncmp(vp->vp_strvalue, date, 5) == 0) {
			RDEBUG2("date set manually to: %s", vp->vp_strvalue);
			mail_ctx->time_status = LOADED;
		}
		if (fr_dbuff_memcpy_in_partial(&out, &mail_ctx->vp_in, SIZE_MAX) < fr_dbuff_remaining(&mail_ctx->vp_in)) return fr_dbuff_used(&out);
		if (fr_dbuff_memcpy_in_partial(&out, &mail_ctx->le_in, SIZE_MAX) < fr_dbuff_remaining(&mail_ctx->le_in)) return fr_dbuff_used(&out);
		vp = fr_cursor_next(&mail_ctx->cursor);
		if (!vp) break;
		fr_dbuff_init(&mail_ctx->le_in, (uint8_t const *)le, 2*sizeof(unsigned char));
		fr_dbuff_init(&mail_ctx->vp_in, (uint8_t const *)vp->vp_strvalue, vp->vp_length);
	}
	/* Add the time this module was called as the timestamp of the email*/
	time_out = FR_SBUFF_TMP(mail_ctx->time_str, sizeof(mail_ctx->time_str));
	if (mail_ctx->time_status == UNLOADED){
		RDEBUG2("The user supplied header elements have been added, preparing the time");
		fr_time_strftime_local(&time_out, fr_time(), "DATE: %a, %d %b %Y %T %z, (%Z) \r\n");
		mail_ctx->time_status = LOADED;
		fr_dbuff_init(&mail_ctx->vp_in, (uint8_t const *)mail_ctx->time_str, strlen(mail_ctx->time_str));
		RDEBUG2("The time has been set to: %s", mail_ctx->time_str);
		if (fr_dbuff_memcpy_in_partial(&out, &mail_ctx->vp_in, SIZE_MAX) < fr_dbuff_remaining(&mail_ctx->vp_in)) return fr_dbuff_used(&out);
		RDEBUG2("The header elements have been added");
	}
	/* Add the final line end to indicate that the header elements are over */
	if (fr_dbuff_memcpy_in_partial(&out, &mail_ctx->le_in, SIZE_MAX) < fr_dbuff_remaining(&mail_ctx->le_in)) return fr_dbuff_used(&out);

	/* Prepare to load in the body elements */
	RDEBUG2("Switching to body_source");
	vp = fr_cursor_iter_by_da_init(&mail_ctx->cursor, &mail_ctx->request->packet->vps, attr_smtp_body);
	fr_dbuff_init(&mail_ctx->vp_in, (uint8_t const *)vp->vp_strvalue, vp->vp_length);
	fr_dbuff_init(&mail_ctx->le_in, (uint8_t const *)le, 2*sizeof(unsigned char));
	mail_ctx->function_source = body_source;
	return fr_dbuff_used(&out);
}
/*
 * cURL does not allow changing of the source function mid request,
 * This function is simply to aggregate the header and body functions
 * into a single callable function
 */
static size_t email_source(char *ptr, size_t size, size_t nmemb, fr_mail_ctx *uctx)
{
	return uctx->function_source(ptr, size, nmemb, uctx);
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

	curl_slist_free_all(mail_ctx->recipients);
	curl_slist_free_all(mail_ctx->header);

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
 *	Check to see if there is enough information to establish a login and to send an email
 *	If there is, attempt to send the email
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_smtp_t const		*inst = talloc_get_type_abort_const(mctx->instance, rlm_smtp_t);
	rlm_smtp_thread_t       	*t = talloc_get_type_abort(mctx->thread, rlm_smtp_thread_t);
	fr_curl_io_request_t     	*randle;
	fr_mail_ctx			*mail_ctx;
	curl_mime			*mime;

	VALUE_PAIR const 		*vp, *smtp_header, *smtp_body, *sender_email, *username, *password;
	static char const 		*le = "\r\n";

	if (fr_pair_find_by_da(request->control, attr_auth_type, TAG_ANY) != NULL) {
		RDEBUG3("Auth-Type is already set.  Not setting 'Auth-Type := %s'", inst->name);
		return RLM_MODULE_NOOP;
	}
	//TODO: talloc set destructor
	username = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);
	password = fr_pair_find_by_da(request->packet->vps, attr_user_password, TAG_ANY);
	smtp_header = fr_pair_find_by_da(request->packet->vps, attr_smtp_header, TAG_ANY);
	smtp_body = fr_pair_find_by_da(request->packet->vps, attr_smtp_body, TAG_ANY);
	sender_email = fr_pair_find_by_da(request->packet->vps, attr_smtp_sender_email, TAG_ANY);

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
	/* Make sure all of the email components are present */
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
	/* prepare mail_ctx to process the request email */
	mail_ctx = talloc_zero(randle, fr_mail_ctx);
	mail_ctx->request 		= request;
	mail_ctx->randle 		= randle;
	mail_ctx->time_status 		= UNLOADED;
	mail_ctx->function_source 	= header_source;
	mail_ctx->time 			= fr_time();

	/* Set the elements of the curl request */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_USERNAME, username->vp_strvalue);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_PASSWORD, password->vp_strvalue);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_DEFAULT_PROTOCOL, "smtp");
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_URL, inst->uri);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_TIMEOUT_MS, fr_time_delta_to_msec(inst->timeout));
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_VERBOSE, 1L);

	/* Set the recipient */
	mail_ctx->recipients = NULL;
       	if(recipients_source(mail_ctx) != 0) {
		RDEBUG2("The recipients list could not be created");
		curl_slist_free_all(mail_ctx->recipients);
		return RLM_MODULE_INVALID;
	}
	mail_ctx->header= NULL;
       	if(header_slist_source(mail_ctx) != 0) {
		RDEBUG2("The header slist could not be created");
		curl_slist_free_all(mail_ctx->header);
		return RLM_MODULE_INVALID;
	}
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_HTTPHEADER, mail_ctx->header);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_MAIL_RCPT, mail_ctx->recipients);
	/* Prepare the cursor to load in the header elements, which will then transition to the body elements */
	vp = fr_cursor_iter_by_da_init(&mail_ctx->cursor, &mail_ctx->request->packet->vps, attr_smtp_header);
	fr_dbuff_init(&mail_ctx->le_in, (uint8_t const *)le, 2*sizeof(unsigned char));
	fr_dbuff_init(&mail_ctx->vp_in, (uint8_t const *)vp->vp_strvalue, vp->vp_length);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_MAIL_FROM, sender_email->vp_strvalue);

	/* Set the email read functions and provide request context*/
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_READFUNCTION, email_source); 	/* Uploads data. Changed to body_source later */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_READDATA, mail_ctx); 		/* All context for the request */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_UPLOAD, 1L); 			/* Tells curl to upload the data */

	/* Set the attachments if there are any*/
	mime = curl_mime_init(randle->candle);
	if(attachments_source(mail_ctx, mime) > 0){
		RDEBUG2("Attachments Added");
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_MIMEPOST, mime);
	}
	/* Initialize tls if it has been set up */
	if (fr_curl_easy_tls_init(randle, &inst->tls) != 0) return RLM_MODULE_INVALID;

	if (fr_curl_io_request_enqueue(t->mhandle, request, randle)) return RLM_MODULE_INVALID;

	return unlang_module_yield(request, mod_authorize_result, NULL, mail_ctx);
error:
	curl_slist_free_all(mail_ctx->recipients);
	curl_slist_free_all(mail_ctx->header);
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
