#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static char *ngx_http_ipbind_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ipbind_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static char *ngx_http_ipbind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_ipbind_commands[] = {
   { ngx_string("ipbind_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_ipbind_zone,
      0,
      0,
      NULL
   },
   {
      ngx_string("print_hello"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_ipbind,
      0,
      0,
      NULL
   },
   ngx_null_command
};

static ngx_http_module_t  ngx_http_ipbind_module_ctx = {
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL
};

ngx_module_t ngx_http_ipbind_module = {
   NGX_MODULE_V1,
   &ngx_http_ipbind_module_ctx,
   ngx_http_ipbind_commands,
   NGX_HTTP_MODULE,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NULL,
   NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_ipbind_handler(ngx_http_request_t *r)
{
   char *ngx_ipbind = "Hello World!";
   size_t sz = strlen(ngx_ipbind);

   r->headers_out.content_type.len = strlen("text/html") - 1;
   r->headers_out.content_type.data = (u_char *) "text/html";
   r->headers_out.status = NGX_HTTP_OK;
   r->headers_out.content_length_n = sz;
   ngx_http_send_header(r);

   ngx_buf_t    *b;
   ngx_chain_t   *out;

   b = ngx_calloc_buf(r->pool);

   out = ngx_alloc_chain_link(r->pool);

   out->buf = b;
   out->next = NULL;

   b->pos = (u_char *) ngx_ipbind;
   b->last = (u_char *) ngx_ipbind + sz;
   b->memory = 1;
   b->last_buf = 1;

   return ngx_http_output_filter(r, out);
}

static char *ngx_http_ipbind_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
   ngx_str_t *value = cf->args->elts;
   ssize_t size = ngx_parse_size(&value[2]);

   if (size == NGX_ERROR) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid zone size \"%V\"", &value[2]);
      return NGX_CONF_ERROR;
   }

   ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf, &value[1], size, &ngx_http_ipbind_module);
   if (shm_zone == NULL) {
       return NGX_CONF_ERROR;
   }

   shm_zone->init = ngx_http_ipbind_init_zone;
   shm_zone->data = NULL;

   return NGX_CONF_OK;
}

static ngx_int_t ngx_http_ipbind_init_zone(ngx_shm_zone_t *shm_zone, void *data) {
   return NGX_OK;
}

static char *ngx_http_ipbind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
   ngx_http_core_loc_conf_t  *clcf;
   clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
   clcf->handler = ngx_http_ipbind_handler;
   return NGX_CONF_OK;
}
