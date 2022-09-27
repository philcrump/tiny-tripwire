/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
 
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <curl/curl.h>

#include "email.h"

/*
static const char *payload_text =
  "Date: Mon, 29 Nov 2010 21:54:29 +1100\r\n"
  "To: " TO_MAIL "\r\n"
  "From: " FROM_MAIL "\r\n"
  "Cc: " CC_MAIL "\r\n"
  "Message-ID: <dcd7cb36-11db-487a-9f3a-e652a9458efd@"
  "rfcpedant.example.org>\r\n"
  "Subject: SMTP example message\r\n"
  "\r\n"
  "The body of the message starts here.\r\n"
  "\r\n"
  "It could be a lot of lines, could be MIME encoded, whatever.\r\n"
  "Check RFC5322.\r\n";
*/

static char *email_body;

struct upload_status {
  size_t bytes_read;
};
 
static size_t payload_source(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct upload_status *upload_ctx = (struct upload_status *)userp;
  const char *data;
  size_t room = size * nmemb;
 
  if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
    return 0;
  }
 
  data = &email_body[upload_ctx->bytes_read];
 
  if(data) {
    size_t len = strlen(data);
    if(room < len)
      len = room;
    memcpy(ptr, data, len);
    upload_ctx->bytes_read += len;
 
    return len;
  }
 
  return 0;
}
 
bool email(config_t *config_ptr, email_t *email_ptr)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  struct curl_slist *recipients = NULL;
  struct upload_status upload_ctx = { 0 };

  if(asprintf(&email_body,
    "To: <%s>\r\n"
    "From: <%s>\r\n"
    "Subject: %s\r\n"
    "\r\n"
    "%s\r\n",
    email_ptr->to,
    email_ptr->from,
    email_ptr->subject,
    email_ptr->message
    ) < 0)
  {
    return false;
  }

  char *email_server_connection_string;

  if(asprintf(&email_server_connection_string,
      "%s://%s:%d",
      config_ptr->smtp_server_usetls ? "smtp" : "smtps",
      config_ptr->smtp_server_hostname,
      config_ptr->smtp_server_port
    ) < 0
  )
  {
    return false;
  }
 
  curl = curl_easy_init();
  if(curl)
  {
    curl_easy_setopt(curl, CURLOPT_URL, email_server_connection_string);

    curl_easy_setopt(curl, CURLOPT_USERNAME, config_ptr->smtp_server_username);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, config_ptr->smtp_server_password);
 
    if(config_ptr->smtp_server_usetls)
    {
      curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    }
    
    if(config_ptr->smtp_server_verifyca)
    {
      curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/certificate.pem");
    }
    else
    {
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
 
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, email_ptr->from);
 
    recipients = curl_slist_append(recipients, email_ptr->to);
    //recipients = curl_slist_append(recipients, CC_MAIL);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
 
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
 
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
 
    /* Send the message */
    res = curl_easy_perform(curl);
 
    /* Check for errors */
    if(res != CURLE_OK)
    {
      fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
 
    /* Free the list of recipients */
    curl_slist_free_all(recipients);
 
    /* Always cleanup */
    curl_easy_cleanup(curl);
  }

  free(email_server_connection_string);
  free(email_body);
 
  return (res == CURLE_OK);
}