/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 2013, Digium, Inc.
 *
 * Joshua Colp <jcolp@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*!
 * \file
 *
 * \brief Sorcery Realtime Object Wizard
 *
 * \author Joshua Colp <jcolp@digium.com>
 */

/*** MODULEINFO
	<support_level>core</support_level>
 ***/

#include "asterisk.h"

#include <regex.h>

#include "asterisk/module.h"
#include "asterisk/sorcery.h"
#include "asterisk/utils.h"
#include "asterisk/lock.h"
#include "asterisk/res_prometheus.h"

/*! \brief They key field used to store the unique identifier for the object */
#define UUID_FIELD "id"

#define METRIC_REQUEST_TOTAL_INDEX  (0)
#define METRIC_REQUEST_TOTAL_FLAG   (1 << METRIC_REQUEST_TOTAL_INDEX)
#define METRIC_REQUEST_TOTAL_NAME   "asterisk_realtime_request_total"
#define METRIC_REQUEST_TOTAL_HELP   "Total requests on sorcery realtime subsystem"

#define METRIC_REQUEST_ERROR_INDEX  (METRIC_REQUEST_TOTAL_INDEX + 1)
#define METRIC_REQUEST_ERROR_FLAG   (1 << METRIC_REQUEST_ERROR_INDEX)
#define METRIC_REQUEST_ERROR_NAME   "asterisk_realtime_request_error"
#define METRIC_REQUEST_ERROR_HELP   "Total error requests on sorcery realtime subsystem"

#define METRIC_REQUEST_MISS_INDEX   (METRIC_REQUEST_ERROR_INDEX + 1)
#define METRIC_REQUEST_MISS_FLAG    (1 << METRIC_REQUEST_MISS_INDEX)
#define METRIC_REQUEST_MISS_NAME    "asterisk_realtime_request_miss"
#define METRIC_REQUEST_MISS_HELP    "Total miss requests on sorcery realtime subsystem"

#define METRICS_COUNT               (METRIC_REQUEST_MISS_INDEX + 1)

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

enum unqualified_fetch {
	UNQUALIFIED_FETCH_NO,
	UNQUALIFIED_FETCH_WARN,
	UNQUALIFIED_FETCH_YES,
	UNQUALIFIED_FETCH_ERROR,
};

struct sorcery_config {
	enum unqualified_fetch fetch;
    struct prometheus_metric metrics[METRICS_COUNT];
    uint64_t metric_values[METRICS_COUNT];
	char family[];
};

static void *sorcery_realtime_open(const char *data);
static int sorcery_realtime_create(const struct ast_sorcery *sorcery, void *data, void *object);
static void *sorcery_realtime_retrieve_id2(const struct ast_sorcery *sorcery, void *data, const char *type, const char *id, int * const errflag);
static void *sorcery_realtime_retrieve_id(const struct ast_sorcery *sorcery, void *data, const char *type, const char *id);
static void *sorcery_realtime_retrieve_fields2(const struct ast_sorcery *sorcery, void *data, const char *type, const struct ast_variable *fields, int * const errflag);
static void *sorcery_realtime_retrieve_fields(const struct ast_sorcery *sorcery, void *data, const char *type, const struct ast_variable *fields);
static void sorcery_realtime_retrieve_multiple2(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects,
                                               const struct ast_variable *fields, int * const errflag);
static void sorcery_realtime_retrieve_multiple(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects,
					     const struct ast_variable *fields);
static void sorcery_realtime_retrieve_regex2(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects, const char *regex, int * const errflag);
static void sorcery_realtime_retrieve_regex(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects, const char *regex);
static void sorcery_realtime_retrieve_prefix2(const struct ast_sorcery *sorcery, void *data, const char *type,
                                             struct ao2_container *objects, const char *prefix, const size_t prefix_len, int * const errflag);
static void sorcery_realtime_retrieve_prefix(const struct ast_sorcery *sorcery, void *data, const char *type,
					     struct ao2_container *objects, const char *prefix, const size_t prefix_len);
static int sorcery_realtime_update(const struct ast_sorcery *sorcery, void *data, void *object);
static int sorcery_realtime_delete(const struct ast_sorcery *sorcery, void *data, void *object);
static void sorcery_realtime_close(void *data);

static void sorcery_realtime_update_metrics(struct sorcery_config * const config, struct ast_flags * const flags);
static void sorcery_realtime_update_metric(struct sorcery_config * const config, int metric_index, uint64_t metric_delta);
static void sorcery_realtime_get_metric_value_total(struct prometheus_metric *metric);
static void sorcery_realtime_get_metric_value_error(struct prometheus_metric *metric);
static void sorcery_realtime_get_metric_value_miss(struct prometheus_metric *metric);
static void sorcery_realtime_get_metric_value(struct prometheus_metric *metric, int metric_index);
static int sorcery_realtime_on_destroy(struct prometheus_metric *metric);

static struct ast_sorcery_wizard realtime_object_wizard = {
	.name = "realtime",
	.open = sorcery_realtime_open,
	.create = sorcery_realtime_create,
	.retrieve_id2 = sorcery_realtime_retrieve_id2,
    .retrieve_id = sorcery_realtime_retrieve_id,
    .retrieve_fields2 = sorcery_realtime_retrieve_fields2,
	.retrieve_fields = sorcery_realtime_retrieve_fields,
    .retrieve_multiple2 = sorcery_realtime_retrieve_multiple2,
	.retrieve_multiple = sorcery_realtime_retrieve_multiple,
    .retrieve_regex2 = sorcery_realtime_retrieve_regex2,
	.retrieve_regex = sorcery_realtime_retrieve_regex,
    .retrieve_prefix2 = sorcery_realtime_retrieve_prefix2,
	.retrieve_prefix = sorcery_realtime_retrieve_prefix,
	.update = sorcery_realtime_update,
	.delete = sorcery_realtime_delete,
	.close = sorcery_realtime_close,
};

static int sorcery_realtime_create(const struct ast_sorcery *sorcery, void *data, void *object)
{
	struct sorcery_config *config = data;
	RAII_VAR(struct ast_variable *, fields, ast_sorcery_objectset_create(sorcery, object), ast_variables_destroy);
	struct ast_variable *id = ast_variable_new(UUID_FIELD, ast_sorcery_object_get_id(object), "");

	if (!fields || !id) {
		ast_variables_destroy(id);
		return -1;
	}

	/* Place the identifier at the front for sanity sake */
	id->next = fields;
	fields = id;

	return (ast_store_realtime_fields(config->family, fields) <= 0) ? -1 : 0;
}

/*! \brief Internal helper function which returns a filtered objectset.
 *
 * The following are filtered out of the objectset:
 * \li The id field. This is returned to the caller in an out parameter.
 * \li Fields that are not registered with sorcery.
 *
 * \param objectset Objectset to filter.
 * \param[out] id The ID of the sorcery object, as found in the objectset.
 * \param sorcery The sorcery instance that is requesting an objectset.
 * \param type The object type
 *
 * \return The filtered objectset
 */
static struct ast_variable *sorcery_realtime_filter_objectset(struct ast_variable *objectset, struct ast_variable **id,
		const struct ast_sorcery *sorcery, const char *type)
{
	struct ast_variable *previous = NULL, *field = objectset;
	struct ast_sorcery_object_type *object_type;

	object_type = ast_sorcery_get_object_type(sorcery, type);
	if (!object_type) {
		ast_log(LOG_WARNING, "Unknown sorcery object type %s. Expect errors\n", type);
		/* Continue since we still want to filter out the id */
	}

	while (field) {
		int remove_field = 0;
		int delete_field = 0;

		if (!strcmp(field->name, UUID_FIELD)) {
			*id = field;
			remove_field = 1;
		} else if (object_type &&
				!ast_sorcery_is_object_field_registered(object_type, field->name)) {
			ast_debug(1, "Filtering out realtime field '%s' from retrieval\n", field->name);
			remove_field = 1;
			delete_field = 1;
		}

		if (remove_field) {
			struct ast_variable *removed;

			if (previous) {
				previous->next = field->next;
			} else {
				objectset = field->next;
			}

			removed = field;
			field = field->next;
			removed->next = NULL;
			if (delete_field) {
				ast_variables_destroy(removed);
			}
		} else {
			previous = field;
			field = field->next;
		}
	}

	ao2_cleanup(object_type);

	return objectset;
}

static void *sorcery_realtime_retrieve_fields2(const struct ast_sorcery *sorcery, void *data, const char *type, const struct ast_variable *fields, int * const errflag)
{
	struct sorcery_config *config = data;
	RAII_VAR(struct ast_variable *, objectset, NULL, ast_variables_destroy);
	RAII_VAR(struct ast_variable *, id, NULL, ast_variables_destroy);
	void *object = NULL;
    int placeholder;
    int * const error = errflag ? errflag : &placeholder;
    struct ast_flags flags = { METRIC_REQUEST_TOTAL_FLAG };

    *error = 0;

	if (!(objectset = ast_load_realtime_fields2(config->family, fields, error))) {
        /* Error occurred or object not found - update metric */
        ast_set_flag(&flags, METRIC_REQUEST_MISS_FLAG | (*error ? METRIC_REQUEST_ERROR_FLAG : 0));
        sorcery_realtime_update_metrics(config, &flags);

		return NULL;
	}

	objectset = sorcery_realtime_filter_objectset(objectset, &id, sorcery, type);

	if (!id
		|| !(object = ast_sorcery_alloc(sorcery, type, id->value))
		|| ast_sorcery_objectset_apply(sorcery, object, objectset)) {
		ao2_cleanup(object);

        /* Required object not found, update metric */
        ast_set_flag(&flags, METRIC_REQUEST_MISS_FLAG);
        sorcery_realtime_update_metrics(config, &flags);
		return NULL;
	}

    /* Object found, update metric */
    sorcery_realtime_update_metrics(config, &flags);

	return object;
}

static void *sorcery_realtime_retrieve_fields(const struct ast_sorcery *sorcery, void *data, const char *type, const struct ast_variable *fields)
{
    return sorcery_realtime_retrieve_fields2(sorcery, data, type, fields, NULL);
}

static void *sorcery_realtime_retrieve_id2(const struct ast_sorcery *sorcery, void *data, const char *type, const char *id, int * const errflag)
{
    struct sorcery_config *config = data;
    struct ast_flags flags = { METRIC_REQUEST_TOTAL_FLAG };
    int placeholder;
    int * const error = errflag ? errflag : &placeholder;
    RAII_VAR(struct ast_variable *, fields, ast_variable_new(UUID_FIELD, id, ""), ast_variables_destroy);
    void *object;

    *error = 0;

    if (!(object = sorcery_realtime_retrieve_fields2(sorcery, data, type, fields, error))) {
        /* Error occurred or object not found - update metric */
        ast_set_flag(&flags, METRIC_REQUEST_MISS_FLAG | (*error ? METRIC_REQUEST_ERROR_FLAG : 0));
    }

    /* Time to update metric */
    sorcery_realtime_update_metrics(config, &flags);

    return object;
}

static void *sorcery_realtime_retrieve_id(const struct ast_sorcery *sorcery, void *data, const char *type, const char *id)
{
    return sorcery_realtime_retrieve_id2(sorcery, data, type, id, NULL);
}

static void sorcery_realtime_retrieve_multiple2(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects, const struct ast_variable *fields, int * const errflag)
{
	struct sorcery_config *config = data;
    struct ast_flags flags = { METRIC_REQUEST_TOTAL_FLAG|METRIC_REQUEST_MISS_FLAG };
    int placeholder;
    int * const error = errflag ? errflag : &placeholder;
	RAII_VAR(struct ast_config *, rows, NULL, ast_config_destroy);
	RAII_VAR(struct ast_variable *, all, NULL, ast_variables_destroy);
	struct ast_category *row = NULL;

    *error = 0;

	if (!fields) {
		char field[strlen(UUID_FIELD) + 6], value[2];

		if (config->fetch == UNQUALIFIED_FETCH_NO) {
			return;
		}
		if (config->fetch == UNQUALIFIED_FETCH_ERROR) {
			ast_log(LOG_ERROR, "Unqualified fetch prevented on %s\n", config->family);
			return;
		}
		if (config->fetch == UNQUALIFIED_FETCH_WARN) {
			ast_log(LOG_WARNING, "Unqualified fetch requested on %s\n", config->family);
		}

		/* If no fields have been specified we want all rows, so trick realtime into doing it */
		snprintf(field, sizeof(field), "%s LIKE", UUID_FIELD);
		snprintf(value, sizeof(value), "%%");

		if (!(all = ast_variable_new(field, value, ""))) {
			return;
		}

		fields = all;
	}

	if (!(rows = ast_load_realtime_multientry_fields2(config->family, fields, error))) {
        /* Error occurred or object not found - update metric */
        ast_set_flag(&flags, METRIC_REQUEST_MISS_FLAG | (*error ? METRIC_REQUEST_ERROR_FLAG : 0));
        sorcery_realtime_update_metrics(config, &flags);

		return;
	}

	while ((row = ast_category_browse_filtered(rows, NULL, row, NULL))) {
		struct ast_variable *objectset = ast_category_detach_variables(row);
		RAII_VAR(struct ast_variable *, id, NULL, ast_variables_destroy);
		RAII_VAR(void *, object, NULL, ao2_cleanup);

		objectset = sorcery_realtime_filter_objectset(objectset, &id, sorcery, type);

		if (id
			&& (object = ast_sorcery_alloc(sorcery, type, id->value))
			&& !ast_sorcery_objectset_apply(sorcery, object, objectset)) {
			ao2_link(objects, object);

            /* Clear MISS flag because some object(s) found */
            ast_clear_flag(&flags, METRIC_REQUEST_MISS_FLAG);
		}

		ast_variables_destroy(objectset);
	}

    /* Update metrics*/
    sorcery_realtime_update_metrics(config, &flags);
}

static void sorcery_realtime_retrieve_multiple(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects, const struct ast_variable *fields)
{
    sorcery_realtime_retrieve_multiple2(sorcery, data, type, objects, fields, NULL);
}

static void sorcery_realtime_retrieve_regex2(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects, const char *regex, int * const errflag)
{
    struct sorcery_config *config = data;
    struct ast_flags flags = { METRIC_REQUEST_TOTAL_FLAG };
    int placeholder;
    int * const error = errflag ? errflag : &placeholder;
	char field[strlen(UUID_FIELD) + 6], value[strlen(regex) + 3];
	RAII_VAR(struct ast_variable *, fields, NULL, ast_variables_destroy);

    *error = 0;

	if (!ast_strlen_zero(regex)) {
		/* The realtime API provides no direct ability to do regex so for now we support a limited subset using pattern matching */
		snprintf(field, sizeof(field), "%s LIKE", UUID_FIELD);
		if (regex[0] == '^') {
			snprintf(value, sizeof(value), "%s%%", regex + 1);
		} else {
			snprintf(value, sizeof(value), "%%%s%%", regex);
		}

		if (!(fields = ast_variable_new(field, value, ""))) {
			return;
		}
	}

	sorcery_realtime_retrieve_multiple2(sorcery, data, type, objects, fields, error);

    if (*error) {
        ast_set_flag(&flags, METRIC_REQUEST_ERROR_FLAG | METRIC_REQUEST_MISS_FLAG);
    }

    sorcery_realtime_update_metrics(config, &flags);
}

static void sorcery_realtime_retrieve_regex(const struct ast_sorcery *sorcery, void *data, const char *type, struct ao2_container *objects, const char *regex)
{
    return sorcery_realtime_retrieve_regex2(sorcery, data, type, objects, regex, NULL);
}

static void sorcery_realtime_retrieve_prefix2(const struct ast_sorcery *sorcery, void *data, const char *type,
					     struct ao2_container *objects, const char *prefix, const size_t prefix_len, int * const errflag)
{
    struct sorcery_config *config = data;
    struct ast_flags flags = { METRIC_REQUEST_TOTAL_FLAG };
    int placeholder;
    int * const error = errflag ? errflag : &placeholder;
	char field[strlen(UUID_FIELD) + 6], value[prefix_len + 2];
	RAII_VAR(struct ast_variable *, fields, NULL, ast_variables_destroy);

    *error = 0;

    if (prefix_len) {
		snprintf(field, sizeof(field), "%s LIKE", UUID_FIELD);
		snprintf(value, sizeof(value), "%.*s%%", (int) prefix_len, prefix);
		if (!(fields = ast_variable_new(field, value, ""))) {
			return;
		}
	}

	sorcery_realtime_retrieve_multiple2(sorcery, data, type, objects, fields, error);

    if (*error) {
        ast_set_flag(&flags, METRIC_REQUEST_ERROR_FLAG | METRIC_REQUEST_MISS_FLAG);
    }

    sorcery_realtime_update_metrics(config, &flags);
}

static void sorcery_realtime_retrieve_prefix(const struct ast_sorcery *sorcery, void *data, const char *type,
                                             struct ao2_container *objects, const char *prefix, const size_t prefix_len)
{
    return sorcery_realtime_retrieve_prefix2(sorcery, data, type, objects, prefix, prefix_len, NULL);
}

static int sorcery_realtime_update(const struct ast_sorcery *sorcery, void *data, void *object)
{
	struct sorcery_config *config = data;
	RAII_VAR(struct ast_variable *, fields, ast_sorcery_objectset_create(sorcery, object), ast_variables_destroy);

	if (!fields) {
		return -1;
	}

	return (ast_update_realtime_fields(config->family, UUID_FIELD, ast_sorcery_object_get_id(object), fields) < 0) ? -1 : 0;
}

static int sorcery_realtime_delete(const struct ast_sorcery *sorcery, void *data, void *object)
{
	struct sorcery_config *config = data;

	return (ast_destroy_realtime_fields(config->family, UUID_FIELD, ast_sorcery_object_get_id(object), NULL) <= 0) ? -1 : 0;
}

static void sorcery_realtime_update_metrics(struct sorcery_config * const config, struct ast_flags * const flags)
{
    if (ast_test_flag(flags, METRIC_REQUEST_TOTAL_FLAG)) {
        sorcery_realtime_update_metric(config, METRIC_REQUEST_TOTAL_INDEX, 1);
    }

    if (ast_test_flag(flags, METRIC_REQUEST_ERROR_FLAG)) {
        sorcery_realtime_update_metric(config, METRIC_REQUEST_ERROR_INDEX, 1);
    }

    if (ast_test_flag(flags, METRIC_REQUEST_MISS_FLAG)) {
        sorcery_realtime_update_metric(config, METRIC_REQUEST_MISS_INDEX, 1);
    }
}

static void sorcery_realtime_update_metric(struct sorcery_config * const config, int metric_index, uint64_t metric_delta)
{
    struct prometheus_metric * const metric = &config->metrics[metric_index];

    ast_mutex_lock(&metric->lock);

    config->metric_values[metric_index] += metric_delta;

    if (NULL == metric->get_metric_value) {
        /* Metric not registered yet*/
        metric->on_destroy = sorcery_realtime_on_destroy;

        switch (metric_index) {
            case METRIC_REQUEST_TOTAL_INDEX:
                metric->get_metric_value = sorcery_realtime_get_metric_value_total;
                break;
            case METRIC_REQUEST_ERROR_INDEX:
                metric->get_metric_value = sorcery_realtime_get_metric_value_error;
                break;
            case METRIC_REQUEST_MISS_INDEX:
                metric->get_metric_value = sorcery_realtime_get_metric_value_miss;
                break;
            default:
                DO_CRASH_NORETURN;
        }

        ast_mutex_unlock(&metric->lock);

        if (prometheus_metric_register(metric)) {
            /* Metric still not registered */
            ast_mutex_lock(&metric->lock);
            metric->get_metric_value = NULL;
            metric->on_destroy = NULL;
            ast_mutex_unlock(&metric->lock);
        }
    } else {
        /* Metric already registered */
        ast_mutex_unlock(&metric->lock);
    }
}

static void sorcery_realtime_get_metric_value_total(struct prometheus_metric *metric)
{
    sorcery_realtime_get_metric_value(metric, METRIC_REQUEST_TOTAL_INDEX);
}

static void sorcery_realtime_get_metric_value_error(struct prometheus_metric *metric)
{
    sorcery_realtime_get_metric_value(metric, METRIC_REQUEST_ERROR_INDEX);
}

static void sorcery_realtime_get_metric_value_miss(struct prometheus_metric *metric)
{
    sorcery_realtime_get_metric_value(metric, METRIC_REQUEST_MISS_INDEX);
}

static void sorcery_realtime_get_metric_value(struct prometheus_metric *metric, int metric_index)
{
    struct sorcery_config * const config = container_of(metric, struct sorcery_config, metrics[metric_index]);

    snprintf(metric->value,
             sizeof(metric->value),
             "%" PRIu64,
            config->metric_values[metric_index]);
}

static int sorcery_realtime_on_destroy(struct prometheus_metric *metric)
{
    metric->get_metric_value = NULL;
    metric->on_destroy = NULL;

    /* Don't destroy metric by res_prometheus module */
    return -2;
}

static void *sorcery_realtime_open(const char *data)
{
	struct sorcery_config *config;
	char *tmp;
	char *family;
	char *option;
    char eid_str[32];
    int i;

	/* We require a prefix for family string generation, or else stuff could mix together */
	if (ast_strlen_zero(data)) {
		return NULL;
	}

	tmp = ast_strdupa(data);
	family = strsep(&tmp, ",");

	if (!ast_realtime_is_mapping_defined(family)) {
		return NULL;
	}

	config = ast_calloc(1, sizeof(*config) + strlen(family) + 1);
	if (!config) {
		return NULL;
	}

	strcpy(config->family, family); /* Safe */
	config->fetch = UNQUALIFIED_FETCH_YES;

	while ((option = strsep(&tmp, ","))) {
		char *name = strsep(&option, "=");
		char *value = option;

		if (!strcasecmp(name, "allow_unqualified_fetch")) {
			if (ast_strlen_zero(value) || !strcasecmp(value, "yes")) {
				config->fetch = UNQUALIFIED_FETCH_YES;
			} else if (!strcasecmp(value, "no")) {
				config->fetch = UNQUALIFIED_FETCH_NO;
			} else if (!strcasecmp(value, "warn")) {
				config->fetch = UNQUALIFIED_FETCH_WARN;
			} else if (!strcasecmp(value, "error")) {
				config->fetch = UNQUALIFIED_FETCH_ERROR;
			} else {
				ast_log(LOG_ERROR, "Unrecognized value in %s:%s: '%s'\n", family, name, value);
				return NULL;
			}
		} else {
			ast_log(LOG_ERROR, "Unrecognized option in %s: '%s'\n", family, name);
			return NULL;
		}
	}

    ast_eid_to_str(eid_str, sizeof(eid_str), &ast_eid_default);

    for (i = 0;i < ARRAY_LEN(config->metrics);i++) {
        struct prometheus_metric *metric = &config->metrics[i];

        metric->allocation_strategy = PROMETHEUS_METRIC_ALLOCD;
        ast_mutex_init(&metric->lock);

        switch (i) {
        case METRIC_REQUEST_TOTAL_INDEX:
            metric->type = PROMETHEUS_METRIC_COUNTER;
            ast_copy_string(metric->name, METRIC_REQUEST_TOTAL_NAME, sizeof(metric->name));
            metric->help = METRIC_REQUEST_TOTAL_HELP;
            break;
        case METRIC_REQUEST_ERROR_INDEX:
            metric->type = PROMETHEUS_METRIC_COUNTER;
            ast_copy_string(metric->name, METRIC_REQUEST_ERROR_NAME, sizeof(metric->name));
            metric->help = METRIC_REQUEST_ERROR_HELP;
            break;
        case METRIC_REQUEST_MISS_INDEX:
            metric->type = PROMETHEUS_METRIC_COUNTER;
            ast_copy_string(metric->name, METRIC_REQUEST_MISS_NAME, sizeof(metric->name));
            metric->help = METRIC_REQUEST_MISS_HELP;
            break;
        default:
            DO_CRASH_NORETURN;
        }

        PROMETHEUS_METRIC_SET_LABEL(metric, 0, "eid", eid_str);
        PROMETHEUS_METRIC_SET_LABEL(metric, 1, "family", family);

        /* Attempt to initialize and register metric.
         * Note: this call can be successful only if module res_prometheus already loaded. */
        sorcery_realtime_update_metric(config, i, 0);
    }

	return config;
}

static void sorcery_realtime_close(void *data)
{
    struct sorcery_config *config = data;
    int i;

    for (i = 0;i < ARRAY_LEN(config->metrics);i++) {
        struct prometheus_metric *metric = &config->metrics[i];

        if (prometheus_metric_unregister(metric)) {
            /* May be metric not registered yet, simple destroy it */
            prometheus_metric_free(metric);
        }
    }

	ast_free(data);
}

static int load_module(void)
{
	if (ast_sorcery_wizard_register(&realtime_object_wizard)) {
		return AST_MODULE_LOAD_DECLINE;
	}

	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	ast_sorcery_wizard_unregister(&realtime_object_wizard);
	return 0;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_GLOBAL_SYMBOLS | AST_MODFLAG_LOAD_ORDER, "Sorcery Realtime Object Wizard",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_REALTIME_DRIVER,
);
