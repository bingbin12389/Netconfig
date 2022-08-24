/* Define data structure */
struct example {
	struct cont_t {
		const char *l;
		uint64_t l_num;
		uint64_t *l_list_num;
		uint64_t l_list_num_count;
		char **l_list_string;
		uint64_t l_list_string_count;
	} cont;
	
	struct exlist_t {
		const char *name;
		uint64_t leaf1;
		struct exlist_t *next;
	} *exlist;

	struct stats_t {
		uint64_t counter;
	} stats;

	pthread_mutex_t lock;
};

/* Init, destroy function */
void example_init(void);
void example_destroy(void);

/* Callback function */
/* RW object */
int l_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
    uint32_t request_id, void *private_data);
int l_num_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
    uint32_t request_id, void *private_data);
int l_list_num_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
    uint32_t request_id, void *private_data);
int l_list_string_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
    uint32_t request_id, void *private_data);
int exlist_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
    uint32_t request_id, void *private_data);
/* RO object */
int stats_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath,
	uint32_t request_id, struct lyd_node **parent, void *private_data);
/* RPC */
int rpc_oper_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
	uint32_t request_id, struct lyd_node *output, void *private_data);
