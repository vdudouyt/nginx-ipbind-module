#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdbool.h>

static void *ngx_http_ipbind_create_conf(ngx_conf_t *cf);
static char *ngx_http_ipbind_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ipbind_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static char *ngx_http_ipbind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ipbind_postaccess_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_ipbind_init(ngx_conf_t *cf);

typedef struct {
   ngx_shm_zone_t *shm_zone;
} ngx_http_ipbind_conf_t;

typedef struct {
   // shared memory
   ngx_rbtree_t rbtree;
   ngx_rbtree_node_t sentinel;
} ngx_http_ipbind_shctx_t;

typedef struct {
   ngx_str_node_t node;
   ngx_str_t addr_text;
} ngx_http_ipbind_node_t;

static ngx_command_t  ngx_http_ipbind_commands[] = {
   { ngx_string("ipbind_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_ipbind_zone,
      0,
      0,
      NULL
   },
   {
      ngx_string("ipbind"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ipbind,
      0,
      0,
      NULL
   },
   ngx_null_command
};

static ngx_http_module_t  ngx_http_ipbind_module_ctx = {
   NULL,
   ngx_http_ipbind_init, /* postconfiguration */
   NULL,
   NULL,
   NULL,
   NULL,
   ngx_http_ipbind_create_conf,
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
   ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "uri=%V ip=%V", &r->uri, &r->connection->addr_text);

   ngx_http_ipbind_conf_t *ipbindcf = ngx_http_get_module_loc_conf(r, ngx_http_ipbind_module);
   ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) ipbindcf->shm_zone->shm.addr;
   ngx_http_ipbind_shctx_t *shctx = ipbindcf->shm_zone->data;

   ngx_shmtx_lock(&shpool->mutex);
   uint32_t hash = ngx_hash_key(r->uri.data, r->uri.len);
   ngx_http_ipbind_node_t *node = (ngx_http_ipbind_node_t *) ngx_str_rbtree_lookup(&shctx->rbtree, &r->uri, hash);

   bool ip_check_ok;

   if(node) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "Access record found: uri=%V ip=%V",
         &node->node.str, &node->addr_text);
      ip_check_ok = node->addr_text.len == r->connection->addr_text.len && ngx_strncmp(node->addr_text.data, r->connection->addr_text.data, node->addr_text.len) == 0;
   } else {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "URI not accessed yet");
      ip_check_ok = true;
   }

   ngx_shmtx_unlock(&shpool->mutex);

   if(!ip_check_ok && node) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
         "access denied: %V expected but %V found", &node->addr_text, &r->connection->addr_text);
   }

   return ip_check_ok ? NGX_DECLINED : NGX_HTTP_FORBIDDEN;
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
   ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

   ngx_http_ipbind_shctx_t *shctx = ngx_slab_alloc(shpool, sizeof(ngx_http_ipbind_shctx_t));
   shm_zone->data = shctx;
   ngx_rbtree_init(&shctx->rbtree, &shctx->sentinel, ngx_str_rbtree_insert_value);
   return NGX_OK;
}

static char *ngx_http_ipbind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
   ngx_http_ipbind_conf_t *ipbindcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_ipbind_module);
   if(ipbindcf == NULL) {
      return NGX_CONF_ERROR;
   }

   ngx_str_t *value = cf->args->elts;
   ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf, &value[1], 0, &ngx_http_ipbind_module);
   if (shm_zone == NULL) {
      return NGX_CONF_ERROR;
   }

   ipbindcf->shm_zone = shm_zone;

   ngx_http_core_loc_conf_t  *clcf;
   clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
   clcf->handler = ngx_http_ipbind_handler;

   return NGX_CONF_OK;
}

static ngx_int_t ngx_http_ipbind_init(ngx_conf_t *cf) {
   ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
   ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
   if (h == NULL) {
       return NGX_ERROR;
   }

   *h = ngx_http_ipbind_postaccess_handler;
   return NGX_OK;
}

static ngx_int_t ngx_http_ipbind_postaccess_handler(ngx_http_request_t *r) {
   if(r->error_page) {
      return NGX_OK; // not interested / mitigate memory extinction attacks
   }

   ngx_http_ipbind_conf_t *ipbindcf = ngx_http_get_module_loc_conf(r, ngx_http_ipbind_module);
   ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) ipbindcf->shm_zone->shm.addr;
   ngx_http_ipbind_shctx_t *shctx = ipbindcf->shm_zone->data;
   uint32_t hash = ngx_hash_key(r->uri.data, r->uri.len);

   ngx_shmtx_lock(&shpool->mutex);
   ngx_http_ipbind_node_t *node = ngx_slab_calloc_locked(shpool, sizeof(ngx_http_ipbind_node_t) + r->uri.len + r->connection->addr_text.len);

   if(!node) {
      ngx_shmtx_unlock(&shpool->mutex);
      // something went wrong, hope to see calloc failure message in error_log
      return NGX_OK;
   }

   node->node.node.key = hash;
   node->node.str.data = (u_char *) node + sizeof(ngx_http_ipbind_node_t);
   node->node.str.len = r->uri.len;
   ngx_memcpy(node->node.str.data, r->uri.data, r->uri.len);

   node->addr_text.data = (u_char *) node + sizeof(ngx_http_ipbind_node_t) + r->uri.len;
   node->addr_text.len = r->connection->addr_text.len;
   ngx_memcpy(node->addr_text.data, r->connection->addr_text.data, r->connection->addr_text.len);

   ngx_rbtree_insert(&shctx->rbtree, &node->node.node);
   ngx_shmtx_unlock(&shpool->mutex);
   return NGX_OK;
}

static void *ngx_http_ipbind_create_conf(ngx_conf_t *cf) {
    ngx_http_ipbind_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ipbind_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->shm_zone = NULL;
    return conf;
}
