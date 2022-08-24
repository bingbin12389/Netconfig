struct example example_data; 

void example_init(void)
{
	pthread_mutex_init(&example_data.lock, NULL);
}

void example_destroy(void)
{
	pthread_mutex_destroy(&example_data.lock);
}

/* Leaf string */
/* examples:example/cont/l */
int l_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath, sr_event_t UNUSED(event),
    uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
	sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list;
    char *xpath2;
    bool prev_dflt;
    int rc;
    struct ly_ctx *ly_ctx;

    ly_ctx = (struct ly_ctx *)sr_get_context();

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM;
        return SR_ERR_NOMEM;
    }

    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        printf("Getting changes iter failed (%s).\n", sr_strerror(rc));
        return rc;
    }

    pthread_mutex_lock(&example_data.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
    	if (!strcmp(node->schema->name, "l")) {
    		switch (op) {
    		case SR_OP_CREATED:
    		case SR_OP_MODIFIED:
    			lydict_remove(ly_ctx, example_data.cont.l);
    			example_data.cont.l = lydict_insert(ly_ctx, ((struct lyd_node_leaf_list *)node)->value_str, 0);
    			break;
    		case SR_OP_DELETED:
    			lydict_remove(ly_ctx, example_data.cont.l);
    			example_data.cont.l = NULL;
    			break;
    		case SR_OP_MOVED:
    		default:
    			pthread_mutex_unlock(&example_data.lock);
    			return SR_ERR_INTERNAL;
    		}
    	}
    }

    pthread_mutex_unlock(&example_data.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
    	printf("Getting next change failed (%s).\n", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* Leaf number */
/* examples:example/cont/l-num */
int l_num_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath, sr_event_t UNUSED(event),
    uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
	sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list;
    char *xpath2;
    bool prev_dflt;
    int rc;
    struct ly_ctx *ly_ctx;

    ly_ctx = (struct ly_ctx *)sr_get_context();

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM;
        return SR_ERR_NOMEM;
    }

    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        printf("Getting changes iter failed (%s).\n", sr_strerror(rc));
        return rc;
    }

    pthread_mutex_lock(&example_data.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
    	if (!strcmp(node->schema->name, "l-num")) {
    		switch (op) {
    		case SR_OP_CREATED:
    		case SR_OP_MODIFIED:
    			example_data.cont.l_num = ((struct lyd_node_leaf_list *)node)->value.uint64;
    			break;
    		case SR_OP_DELETED:
    		case SR_OP_MOVED:
    		default:
    			break;
    		}
    	}
    }

    pthread_mutex_unlock(&example_data.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
    	printf("Getting next change failed (%s).\n", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* Leaf-list number */
/* examples:example/cont/l-list-num */
int l_list_num_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath, sr_event_t UNUSED(event),
    uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
	sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list;
    char *xpath2;
    bool prev_dflt;
    int rc;
    struct ly_ctx *ly_ctx;

    int l_list_num_t;
    void *mem;
    int i;

    ly_ctx = (struct ly_ctx *)sr_get_context();

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM;
        return SR_ERR_NOMEM;
    }

    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        printf("Getting changes iter failed (%s).\n", sr_strerror(rc));
        return rc;
    }

    pthread_mutex_lock(&example_data.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
    	if (!strcmp(node->schema->name, "l-list-num")) {
    		if ((op == SR_OP_DELETED) && !example_data.cont.l_list_num) {
    			continue;
    		}
    		l_list_num_t = ((struct lyd_node_leaf_list *)node)->value.uint64;

    		switch (op) {
    		case SR_OP_CREATED:
    			mem = realloc(example_data.cont.l_list_num, (example_data.cont.l_list_num_count + 1) * sizeof *example_data.cont.l_list_num);
    			if (!mem) {
    				EMEM;
    				pthread_mutex_unlock(&example_data.lock);
    				return SR_ERR_NOMEM;
    			}
    			example_data.cont.l_list_num = mem;
    			example_data.cont.l_list_num[example_data.cont.l_list_num_count] = l_list_num_t;
    			++example_data.cont.l_list_num_count;
    			break;
    		case SR_OP_DELETED:
    			for (i = 0; i < example_data.cont.l_list_num_count; ++i) {
    				if (example_data.cont.l_list_num[i] == l_list_num_t) {
    					break;
    				}
    			}
    			if (i >= example_data.cont.l_list_num_count) {
    				printf("l-list-num index failed\n");
    				pthread_mutex_unlock(&example_data.lock);
    				return SR_ERR_INTERNAL;
    			}

    			/* Delete it */
    			--example_data.cont.l_list_num_count;
    			if (i < example_data.cont.l_list_num_count) {
    				example_data.cont.l_list_num[i] = example_data.cont.l_list_num[example_data.cont.l_list_num_count];
    			}
    			if (!example_data.cont.l_list_num_count) {
    				free(example_data.cont.l_list_num);
    				example_data.cont.l_list_num = NULL;
    			}
    			break;
    		case SR_OP_MODIFIED:
    		case SR_OP_MOVED:
    		default:
    			pthread_mutex_unlock(&example_data.lock);
    			return SR_ERR_INTERNAL;
    		}
    	}
    }

    pthread_mutex_unlock(&example_data.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
    	printf("Getting next change failed (%s).\n", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* Leaf-list string */
/* examples:example/cont/l-list-string */
int l_list_string_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath, sr_event_t UNUSED(event),
    uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
	sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list;
    char *xpath2;
    bool prev_dflt;
    int rc;
    struct ly_ctx *ly_ctx;

    const char *l_list_string_t;
    void *mem;
    int i;

    ly_ctx = (struct ly_ctx *)sr_get_context();

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM;
        return SR_ERR_NOMEM;
    }

    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        printf("Getting changes iter failed (%s).\n", sr_strerror(rc));
        return rc;
    }

    pthread_mutex_lock(&example_data.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
    	if (!strcmp(node->schema->name, "l-list-string")) {
    		if ((op == SR_OP_DELETED) && !example_data.cont.l_list_string) {
    			continue;
    		}
    		l_list_string_t = ((struct lyd_node_leaf_list *)node)->value_tr;

    		switch (op) {
    		case SR_OP_CREATED:
    			mem = realloc(example_data.cont.l_list_string, (example_data.cont.l_list_string_count + 1) * sizeof *example_data.cont.l_list_string);
    			if (!mem) {
    				EMEM;
    				pthread_mutex_unlock(&example_data.lock);
    				return SR_ERR_NOMEM;
    			}
    			example_data.cont.l_list_string = mem;
    			example_data.cont.l_list_string[example_data.cont.l_list_string_count] = (char *)lydict_insert(ly_ctx, l_list_string_t, 0);
    			++example_data.cont.l_list_string_count;
    			break;
    		case SR_OP_DELETED:
    			for (i = 0; i < example_data.cont.l_list_string_count; ++i) {
    				if (example_data.cont.l_list_string[i] == l_list_string_t) {
    					break;
    				}
    			}
    			if (i >= example_data.cont.l_list_string_count) {
    				printf("l-list-string index failed\n");
    				pthread_mutex_unlock(&example_data.lock);
    				return SR_ERR_INTERNAL;
    			}

    			/* Delete it */
    			lydict_remove(ly_ctx, example_data.cont.l_list_string[i]);
    			--example_data.cont.l_list_string_count;
    			if (i < example_data.cont.l_list_string_count) {
    				example_data.cont.l_list_string[i] = example_data.cont.l_list_string[example_data.cont.l_list_string_count];
    			}
    			if (!example_data.cont.l_list_string_count) {
    				free(example_data.cont.l_list_string);
    				example_data.cont.l_list_string = NULL;
    			}
    			break;
    		case SR_OP_MODIFIED:
    		case SR_OP_MOVED:
    		default:
    			pthread_mutex_unlock(&example_data.lock);
    			return SR_ERR_INTERNAL;
    		}
    	}
    }

    pthread_mutex_unlock(&example_data.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
    	printf("Getting next change failed (%s).\n", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* List */
/* examples:example/exlist */
int exlist_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *xpath, sr_event_t UNUSED(event),
    uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
	sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list;
    char *xpath2;
    bool prev_dflt;
    int rc;
    struct ly_ctx *ly_ctx;

    const char *name_t;
    struct exlist_t *exlist_temp = NULL, *prev_exlist = NULL;

    ly_ctx = (struct ly_ctx *)sr_get_context();

    if (asprintf(&xpath2, "%s//.", xpath) == -1) {
        EMEM;
        return SR_ERR_NOMEM;
    }
    rc = sr_get_changes_iter(session, xpath2, &iter);
    free(xpath2);
    if (rc != SR_ERR_OK) {
        printf("Getting changes iter failed (%s).\n", sr_strerror(rc));
        return rc;
    }

    pthread_mutex_lock(&example_data.lock);

    while ((rc = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
    	if (!strcmp(node->schema->name, "exlist")) {
    		/* name must be present */
    		if (strcmp(node->child->schema->name, "name")) {
    			printf("name of exlist not found\n");
    			pthread_mutex_unlock(&example_data.lock);
    			return SR_ERR_NOT_FOUND;
    		}
    		name_t = ((struct lyd_node_leaf_list *)node->child)->value_tr;

    		switch (op) {
    		case SR_OP_MOVED:
    			/* Find it */
    			prev_exlist = NULL;
    			for (exlist_temp = example_data.exlist; exlist_temp && (exlist_temp->name != name_t); exlist_temp = exlist_temp->next) {
    				prev_exlist = exlist_temp;
    			}
    			if (exlist_temp == NULL) {
    				printf("exlist not found to move\n");
    				pthread_mutex_unlock(&example_data.lock);
    				return SR_ERR_NOT_FOUND;
    			}
    			/* Unlink it */
    			if (prev_exlist) {
    				prev_exlist->next = exlist_temp->next;
    			} else {
    				example_data.exlist = exlist_temp->next;
    			}
    			/* Fallthrough */
    		case SR_OP_CREATED:
    			if (op == SR_OP_CREATED) {
    				/* Create new */
    				exlist_temp = calloc(1, sizeof *exlist_temp);
    				if (!exlist_temp) {
    					EMEM;
    					pthread_mutex_unlock(&example_data.lock);
    					return SR_ERR_NOMEM;
    				}
    				exlist_temp->name = lydict_insert(ly_ctx, name_t, 0);
    			}

    			/* Insert after previous */
    			if (prev_exlist) {
    				prev_exlist->next = exlist_temp;
    			} else {
    				example_data.exlist = exlist_temp;
    			}
    			prev_exlist = exlist_temp;
    			break;
    		case SR_OP_DELETED:
    			/* Find it */
    			prev_exlist = NULL;
    			for (exlist_temp = example_data.exlist; exlist_temp && (exlist_temp->name != name_t); exlist_temp = exlist_temp->next) {
    				prev_exlist = exlist_temp;
    			}
    			if (exlist_temp == NULL) {
    				printf("exlist not found to move\n");
    				pthread_mutex_unlock(&example_data.lock);
    				return SR_ERR_NOT_FOUND;
    			}
    			/* Delete it */
    			lydict_remove(ly_ctx, exlist_temp->name);

    			if (prev_exlist) {
    				prev_exlist->next = exlist_temp->next;
    			} else {
    				example_data.exlist = exlist_temp->next;
    			}
    			free(exlist_temp);
    			exlist_temp = NULL;
    			break;
    		case SR_OP_MODIFIED:
    		default:
    			pthread_mutex_unlock(&example_data.lock);
    			return SR_ERR_INTERNAL;
    		}
    	} else {
    		/* name must be present */
    		if (!strcmp(node->parent->schema->name, "exlist")) {
    			if (strcmp(node->parent->child->schema->name, "name")) {
	    			printf("name of exlist not found\n");
	    			pthread_mutex_unlock(&example_data.lock);
	    			return SR_ERR_NOT_FOUND;
	    		}
	    		name_t = ((struct lyd_node_leaf_list *)node->parent->child)->value_tr;
	    		for (exlist_temp = example_data.exlist; exlist_temp && (exlist_temp->name != name_t); exlist_temp = exlist_temp->next);

	    		if ((op == SR_OP_DELETED) && !exlist_temp) {
	    			/* Even parent was delete */
	    			continue;
	    		}
	    		if (exlist_temp == NULL) {
	    			printf("exlist not found\n");
    				pthread_mutex_unlock(&example_data.lock);
    				return SR_ERR_NOT_FOUND;
	    		}
    		}

    		if (!strcmp(node->schema->name, "name")) {
    			switch (op) {
	    		case SR_OP_CREATED:
	    		case SR_OP_MODIFIED:
	    			lydict_remove(ly_ctx, exlist_temp->name);
	    			exlist_temp->name = lydict_insert(ly_ctx, ((struct lyd_node_leaf_list *)node)->value_str, 0);
	    			break;
	    		case SR_OP_DELETED:
	    			lydict_remove(ly_ctx, exlist_temp->name);
	    			exlist_temp->name = NULL;
	    			break;
	    		case SR_OP_MOVED:
	    		default:
	    			pthread_mutex_unlock(&example_data.lock);
	    			return SR_ERR_INTERNAL;
	    		}
    		} else if (!strcmp(node->schema->name, "leaf1")) {
    			switch (op) {
	    		case SR_OP_CREATED:
	    		case SR_OP_MODIFIED:
	    			exlist_temp->leaf1 = ((struct lyd_node_leaf_list *)node)->value.uint64;
	    			break;
	    		case SR_OP_DELETED:
	    		case SR_OP_MOVED:
	    		default:
	    			break;
	    		}
    		}
    	}
    }

    pthread_mutex_unlock(&example_data.lock);

    sr_free_change_iter(iter);
    if (rc != SR_ERR_NOT_FOUND) {
    	printf("Getting next change failed (%s).\n", sr_strerror(rc));
        return rc;
    }

    return SR_ERR_OK;
}

/* State data */
/* examples:example/exlist/stats/counter */
int stats_cb(sr_session_ctx_t *UNUSED(session), const char *UNUSED(module_name), const char *path, const char *UNUSED(request_xpath),
	uint32_t UNUSED(request_id), struct lyd_node **parent, void *UNUSED(private_data))
{
	struct lyd_node *node;
	char num_str[11];

	if (*parent == NULL) {
		printf("Parent is NULL\n");
		return SR_ERR_INTERNAL;
	}

	pthread_mutex_lock(&example_data.lock);
	sprintf(num_str, "%u", example_data.stats.counter);
	node = lyd_new_path(*parent, NULL, "counter", num_str, 0, 0);
	pthread_mutex_unlock(&example_data.lock);

	if (!node) {
		return SR_ERR_INTERNAL;
	}

	return SR_ERR_OK;
}

/* RPC */
int rpc_oper_cb(sr_session_ctx_t *UNUSED(session), const char *UNUSED(op_path), const struct lyd_node *input, sr_event_t UNUSED(event),
	uint32_t UNUSED(request_id), struct lyd_node *output, void *UNUSED(private_data))
{
	struct ly_set *nodeset;

	int input_t;
	int output_t;

	/* Input */
	nodeset = lyd_find_path(input, "arg");
	if (nodeset->number) {
		input_t = ((struct lyd_node_leaf_list *)nodeset->set.d[0])->value.uint64;
		/* Using input here */
		/*  */
	}
	ly_set_free(nodeset);

	/* Output */
	/* Change output here */
	/* output = 69; */
	lyd_new_output_leaf(output, NULL, "ret", output, NULL, NULL);

	return SR_ERR_OK;
}
