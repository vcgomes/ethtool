/*
 * preempt.c - netlink implementation of frame preemption settings
 *
 * Implementation of "ethtool --{show,set}-frame-preemption <dev>"
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "parser.h"

/* PREEMPT_GET */

static int preempt_get_prep_request(struct nl_socket *nlsk)
{
	int ret;

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_PREEMPT_GET,
				      ETHTOOL_A_PREEMPT_HEADER, 0);
	if (ret < 0)
		return ret;

	return 0;
}

int preempt_get_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_PREEMPT_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	int ret;

	if (nlctx->is_dump || nlctx->is_monitor)
		nlctx->no_banner = false;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return ret;

	nlctx->devname = get_dev_name(tb[ETHTOOL_A_PREEMPT_HEADER]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	printf("Frame preemption settings for %s:\n", nlctx->devname);

	if (tb[ETHTOOL_A_PREEMPT_ENABLED]) {
		int enabled = mnl_attr_get_u8(tb[ETHTOOL_A_PREEMPT_ENABLED]);

		printf("\tenabled: %s\n", enabled ? "enabled" : "not enabled");
	}
	if (tb[ETHTOOL_A_PREEMPT_ADD_FRAG_SIZE]) {
		uint32_t add_frag_size = mnl_attr_get_u32(
			tb[ETHTOOL_A_PREEMPT_ADD_FRAG_SIZE]);

		printf("\tadditional fragment size: %d\n", add_frag_size);
	}
	return MNL_CB_OK;
}

int nl_get_preempt(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	ret = preempt_get_prep_request(nlsk);
	if (ret < 0)
		return ret;
	return nlsock_send_get_request(nlsk, preempt_get_reply_cb);
}

static const struct lookup_entry_u8 fp_values[] = {
	{ .arg = "off",		.val = 0 },
	{ .arg = "on",		.val = 1 },
	{}
};

static const struct param_parser set_preempt_params[] = {
	{
		.arg		= "fp",
		.group		= ETHTOOL_MSG_PREEMPT_SET,
		.type		= ETHTOOL_A_PREEMPT_ENABLED,
		.handler	= nl_parse_lookup_u8,
		.handler_data	= fp_values,
		.min_argc	= 1,
	},
	{
		.arg		= "add-frag-size",
		.group		= ETHTOOL_MSG_PREEMPT_SET,
		.type		= ETHTOOL_A_PREEMPT_ADD_FRAG_SIZE,
		.handler	= nl_parse_direct_u32,
		.min_argc	= 1,
	},
	{}
};

int nl_set_preempt(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_msg_buff *msgbuff;
	struct nl_socket *nlsk;
	int ret;

	nlctx->cmd = "--set-frame-preemption";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->devname = ctx->devname;
	nlsk = nlctx->ethnl_socket;
	msgbuff = &nlsk->msgbuff;

	ret = msg_init(nlctx, msgbuff, ETHTOOL_MSG_PREEMPT_SET,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return 2;
	if (ethnla_fill_header(msgbuff, ETHTOOL_A_PREEMPT_HEADER,
			       ctx->devname, 0))
		return -EMSGSIZE;

	ret = nl_parser(nlctx, set_preempt_params, NULL, PARSER_GROUP_NONE, NULL);
	if (ret < 0)
		return 1;

	ret = nlsock_sendmsg(nlsk, NULL);
	if (ret < 0)
		return 81;
	ret = nlsock_process_reply(nlsk, nomsg_reply_cb, nlctx);
	if (ret == 0)
		return 0;
	else
		return nlctx->exit_code ?: 81;
}
