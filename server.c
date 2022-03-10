#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include "server.h"

volatile sig_atomic_t sig_event_flag = sigev_no_events;

void signal_handler(int signum)
{
        if (signum == SIGTERM || signum == SIGUSR1)
                sig_event_flag = sigev_terminate;
        else if (signum == SIGUSR2)
                sig_event_flag = sigev_restart;
}

void send_string(struct session *ptr, const char *str)
{
        write(ptr->socket_d, str, strlen(str));
}

void broadcast_message(struct session *sess, const char *msg)
{
        while (sess) {
                send_string(sess, msg);
                sess = sess->next;
        }
}

void broadcast_message_except(struct session *sess, struct session *except,
                              const char *msg)
{
        while (sess) {
                if (sess != except)
                        send_string(sess, msg);
                sess = sess->next;
        }
}

void starter_kit(struct session *ptr)
{
        int i;
        ptr->money = money_starter_kit;
        ptr->raw = raw_starter_kit;
        ptr->prod = prod_starter_kit;
        ptr->plants = plants_starter_kit;
        for (i = 0; i < month_plant_build; i++)
                ptr->build[i] = 0;
}

void clear_requests(struct session *ptr)
{
        ptr->sell_count = 0;
        ptr->sell_price = 0;
        ptr->buy_count = 0;
        ptr->buy_price = 0;
        ptr->produce = 0;
}

void greet_player(struct session *ptr)
{
        char buf[128];
        send_string(ptr, "# Welcome to Game Server!\n");
        send_string(ptr, "# Your game ID:\n");
        sprintf(buf, "%% %7d\n\n", ptr->game_id);
        send_string(ptr, buf);
}

void create_session(struct session **sess, int fd, int id)
{
        while (*sess)
                sess = &(*sess)->next;
        *sess = malloc(sizeof(**sess));
        (*sess)->next = NULL;
        (*sess)->socket_d = fd;
        (*sess)->buf_used = 0;
        (*sess)->flag = st_thinking;
        (*sess)->game_id = id;
        starter_kit(*sess);
        clear_requests(*sess);
        (*sess)->sold = 0;
        (*sess)->bought = 0;
        greet_player(*sess);
}

int delete_sessions(struct session **sess)
{
        struct session *tmp;
        int deleted = 0;
        while (*sess) {
                if ((*sess)->flag == st_goodbye) {
                        tmp = *sess;
                        *sess = (*sess)->next;
                        shutdown(tmp->socket_d, 2);
                        close(tmp->socket_d);
                        free(tmp);
                        deleted++;
                } else {
                        sess = &(*sess)->next;
                }
        }
        return deleted;
}

void delete_session_list(struct session *sess)
{
        struct session *tmp;
        while (sess) {
                tmp = sess;
                sess = sess->next;
                shutdown(tmp->socket_d, 2);
                close(tmp->socket_d);
                free(tmp);
        }
}

enum game_command get_command(const char *str)
{
        if (!strcmp(str, "market"))
                return cmd_market;
        if (!strcmp(str, "info"))
                return cmd_info;
        if (!strcmp(str, "sell"))
                return cmd_sell;
        if (!strcmp(str, "buy"))
                return cmd_buy;
        if (!strcmp(str, "prod"))
                return cmd_prod;
        if (!strcmp(str, "build"))
                return cmd_build;
        if (!strcmp(str, "cancel"))
                return cmd_cancel;
        if (!strcmp(str, "turn"))
                return cmd_turn;
        if (!strcmp(str, "view"))
                return cmd_view;
        if (!strcmp(str, "help"))
                return cmd_help;
        return cmd_error;
}

void game_not_started(struct session *ptr, const struct game_info *bank)
{
        char buf[128];
        sprintf(buf, "# %d/%d have already connected\n",
                bank->online, bank->player_amount);
        send_string(ptr, buf);
        send_string(ptr, "# Waiting for players...\n\n");
}

void parse_request(const char *str, struct game_request *req)
{
        char buf[16];
        int res;
        req->argv[0] = 0;
        req->argv[1] = 0;
        res = sscanf(str, "%15s %d %d", buf, &req->argv[0], &req->argv[1]);
        req->cmd = res >= 1 ? get_command(buf) : cmd_empty;
}

void check_request(struct session *ptr, struct game_request *req)
{
        switch (req->cmd) {
        case cmd_prod:
        case cmd_build:
                if (req->argv[0] <= 0) {
                        send_string(ptr, "& You must give a number\n");
                        req->cmd = cmd_error;
                }
                break;
        case cmd_sell:
        case cmd_buy:
                if (req->argv[0] <= 0 || req->argv[1] <= 0) {
                        send_string(ptr, "& You must give two numbers\n");
                        req->cmd = cmd_error;
                }
                break;
        case cmd_error:
                send_string(ptr, "& Unknown command\n");
        default:
                ;
        }
        if (req->cmd == cmd_error) {
                send_string(ptr, "# Type 'help' to get information\n\n");
                return;
        }
        if (ptr->flag == st_endturn && req->cmd != cmd_view &&
            req->cmd != cmd_empty && req->cmd != cmd_market &&
            req->cmd != cmd_info && req->cmd != cmd_help) {
                send_string(ptr, "& This command is unavailable now\n\n");
                req->cmd = cmd_error;
        }
        if (ptr->flag == st_gameover &&
            req->cmd != cmd_empty && req->cmd != cmd_market &&
            req->cmd != cmd_info && req->cmd == cmd_help) {
                send_string(ptr, "& Sorry, the game is over for you\n\n");
                req->cmd = cmd_error;
        }
}

void do_market(struct session *ptr, const struct game_info *bank)
{
        char buf[128];
        sprintf(buf, "# Current month is %dth\n", bank->month);
        send_string(ptr, buf);
        send_string(ptr, "# Players still active:\n");
        sprintf(buf, "%%              %d\n", bank->active);
        send_string(ptr, buf);
        send_string(ptr, "# Bank sells:  items  min.price\n");
        sprintf(buf, "%%              %-5d  %d\n",
                bank->raw_units, bank->min_price);
        send_string(ptr, buf);
        send_string(ptr, "# Bank buys:   items  max.price\n");
        sprintf(buf, "%%              %-5d  %d\n",
                bank->prod_units, bank->max_price);
        send_string(ptr, buf);
        send_string(ptr, "\n");
}

void do_info(struct session *ptr, struct session *sess)
{
        char buf[128];
        send_string(ptr, "# Player   Money   Raw   Prod   Plants\n");
        while (sess) {
                if (sess->flag == st_thinking || sess->flag == st_endturn) {
                        sprintf(buf, "%% %-6d   %-5d   %-3d   %-4d   %d\n",
                                sess->game_id, sess->money, sess->raw,
                                sess->prod, sess->plants);
                        send_string(ptr, buf);
                }
                sess = sess->next;
        }
        send_string(ptr, "\n");
}

void do_sell(struct session *ptr, const struct game_request *req,
             const struct game_info *bank)
{
        if (req->argv[0] > bank->prod_units) {
                send_string(ptr, "& Bank buys fewer prod units\n\n");
                return;
        }
        if (req->argv[1] > bank->max_price) {
                send_string(ptr, "& Your price is too high\n\n");
                return;
        }
        if (req->argv[0] > ptr->prod) {
                send_string(ptr, "& You don't have enough prod units\n\n");
                return;
        }
        ptr->sell_count = req->argv[0];
        ptr->sell_price = req->argv[1];
        send_string(ptr, "& Your request is accepted\n\n");
}

void do_buy(struct session *ptr, const struct game_request *req,
            const struct game_info *bank)
{
        if (req->argv[0] > bank->raw_units) {
                send_string(ptr, "& Bank sells fewer raw units\n\n");
                return;
        }
        if (req->argv[1] < bank->min_price) {
                send_string(ptr, "& Your price is too low\n\n");
                return;
        }
        ptr->buy_count = req->argv[0];
        ptr->buy_price = req->argv[1];
        send_string(ptr, "& Your request is accepted\n\n");
}

void do_prod(struct session *ptr, const struct game_request *req)
{
        if (ptr->raw - ptr->produce < req->argv[0]) {
                send_string(ptr, "& You don't have enough raw units\n\n");
                return;
        }
        if (ptr->plants - ptr->produce < req->argv[0]) {
                send_string(ptr, "& You don't have enough plants\n\n");
                return;
        }
        ptr->produce += req->argv[0];
        send_string(ptr, "& Your request is accepted\n\n");
}

void do_build(struct session *ptr, const struct game_request *req)
{
        char buf[128];
        int cost = req->argv[0] * plant_price / 2;
        if (ptr->money >= cost) {
                ptr->money -= cost;
                ptr->build[month_plant_build - 1] += req->argv[0];
                sprintf(buf, "& Construction started! Payment: $%d\n", cost);
                send_string(ptr, buf);
                sprintf(buf, "# Your balance is $%d\n\n", ptr->money);
                send_string(ptr, buf);
        } else {
                send_string(ptr, "& You don't have enough money\n\n");
        }
}

void do_cancel(struct session *ptr)
{
        clear_requests(ptr);
        send_string(ptr, "& All your requests have been canceled\n\n");
}

void do_turn(struct session *ptr)
{
        ptr->flag = st_endturn;
        send_string(ptr, "& Now only info-commands are available\n\n");
}

void do_view(struct session *ptr)
{
        char buf[128];
        sprintf(buf, "# Your game ID: %d\n", ptr->game_id);
        send_string(ptr, buf);
        sprintf(buf, "# Your balance is $%d\n", ptr->money);
        send_string(ptr, buf);
        sprintf(buf, "# You have %d prod units, %d raw units, %d plants\n",
                ptr->prod, ptr->raw, ptr->plants);
        send_string(ptr, buf);
        sprintf(buf, "# Requested: sell %d for $%d, buy %d for $%d, produce %d",
                ptr->sell_count, ptr->sell_price,
                ptr->buy_count, ptr->buy_price, ptr->produce);
        send_string(ptr, buf);
        send_string(ptr, "\n\n");
}

void do_help(struct session *ptr)
{
        send_string(ptr,
                "# Use commands:\n"
                "# market   - to get the current market status\n"
                "# info     - to get information about players\n"
                "# sell     - to place production sell request\n"
                "# buy      - to place raw buy request\n"
                "# prod     - to manufacture production\n"
                "# build    - to build a new plant\n"
                "# cancel   - to cancel all requests\n"
                "# turn     - to finish work this month\n"
                "# view     - to see your requests\n"
                "# help     - to get this help\n\n"
        );
        send_string(ptr,
                "# Rules of the Game:\n"
                "# Free plant + raw unit + $2000 -> prod unit\n"
                "# Plant can be build in 5 month for $2500+$2500\n"
                "# Monthly expenses are $1000 per plant,\n"
                "# $300 per raw unit, $500 per prod unit\n\n"
        );
}

void execute_command(const char *str, struct session *ptr,
                     struct session *sess, const struct game_info *bank)
{
        struct game_request req;
        if (bank->wait_players) {
                game_not_started(ptr, bank);
                return;
        }
        parse_request(str, &req);
        check_request(ptr, &req);
        switch (req.cmd) {
        case cmd_market:
                do_market(ptr, bank);
                break;
        case cmd_info:
                do_info(ptr, sess);
                break;
        case cmd_sell:
                do_sell(ptr, &req, bank);
                break;
        case cmd_buy:
                do_buy(ptr, &req, bank);
                break;
        case cmd_prod:
                do_prod(ptr, &req);
                break;
        case cmd_build:
                do_build(ptr, &req);
                break;
        case cmd_cancel:
                do_cancel(ptr);
                break;
        case cmd_turn:
                do_turn(ptr);
                break;
        case cmd_view:
                do_view(ptr);
                break;
        case cmd_help:
                do_help(ptr);
                break;
        case cmd_error:
        case cmd_empty:
                ;
        }
}

void check_lf(struct session *ptr, struct session *sess,
              const struct game_info *bank)
{
        int pos, i;
        char *str;
        for (;;) {
                pos = -1;
                for (i = 0; i < ptr->buf_used; i++) {
                        if (ptr->buf[i] == '\n') {
                                pos = i;
                                break;
                        }
                }
                if (pos == -1)
                        return;
                str = malloc(pos + 1);
                memcpy(str, ptr->buf, pos);
                str[pos] = '\0';
                ptr->buf_used -= pos + 1;
                memmove(ptr->buf, ptr->buf + pos + 1, ptr->buf_used);
                if (pos && str[pos - 1] == '\r')
                        str[pos - 1] = '\0';
                execute_command(str, ptr, sess, bank);
                free(str);
        }
}

void read_data(struct session *ptr, struct session *sess,
               struct game_info *bank)
{
        int rc, busy = ptr->buf_used;
        rc = read(ptr->socket_d, ptr->buf + busy, INBUFSIZE - busy);
        if (rc <= 0) {
                if (ptr->flag != st_gameover && !bank->wait_players)
                        bank->active--;
                ptr->flag = st_goodbye;
                return;
        }
        ptr->buf_used += rc;
        check_lf(ptr, sess, bank);
        if (ptr->buf_used >= INBUFSIZE) {
                send_string(ptr, "# String too long...\n\n");
                ptr->buf_used = 0;
        }
}

int compare_prices(const void *bid1, const void *bid2)
{
        return ((struct player_bid *)bid1)->price -
               ((struct player_bid *)bid2)->price;
}

void qsort_offers(struct player_bid *bids, int size)
{
        qsort(bids, size, sizeof(*bids), &compare_prices);
}

void shuffle_offers(struct player_bid *bids, int size)
{
        int i, j;
        struct player_bid tmp;
        for (i = size - 1; i > 0; i--) {
                j = (int)((double)(i + 1) * rand() / (RAND_MAX + 1.0));
                tmp = bids[i];
                bids[i] = bids[j];
                bids[j] = tmp;
        }
}

void take_sell_offers(struct player_bid *bids, struct session *sess)
{
        while (sess) {
                if (sess->flag != st_gameover) {
                        bids->count = sess->sell_count;
                        bids->price = sess->sell_price;
                        bids->player = sess;
                        bids++;
                }
                sess = sess->next;
        }
}

void take_buy_offers(struct player_bid *bids, struct session *sess)
{
        while (sess) {
                if (sess->flag != st_gameover) {
                        bids->count = sess->buy_count;
                        bids->price = sess->buy_price;
                        bids->player = sess;
                        bids++;
                }
                sess = sess->next;
        }
}

void prod_trade(const struct player_bid *bids, int size, int prod)
{
        int i;
        for (i = 0; i < size; i++) {
                if (prod >= bids[i].count) {
                        bids[i].player->sold = bids[i].count;
                        prod -= bids[i].count;
                } else {
                        if (prod) {
                                bids[i].player->sold = prod;
                                prod = 0;
                        } else {
                                bids[i].player->sold = 0;
                        }
                }
        }
}

void raw_trade(const struct player_bid *bids, int size, int raw)
{
        int i;
        for (i = size - 1; i >= 0; i--) {
                if (raw >= bids[i].count) {
                        bids[i].player->bought = bids[i].count;
                        raw -= bids[i].count;
                } else {
                        if (raw) {
                                bids[i].player->bought = raw;
                                raw = 0;
                        } else {
                                bids[i].player->bought = 0;
                        }
                }
        }
}

void send_results(struct session *sess)
{
        char buf[128];
        struct session *tmp;
        broadcast_message(sess, "# Player   Sold   Price   Bought   Price\n");
        for (tmp = sess; tmp; tmp = tmp->next) {
                if (tmp->flag == st_gameover)
                        continue;
                sprintf(buf, "%% %-6d   %-4d   %-5d   %-6d   %d\n",
                        tmp->game_id, tmp->sold, tmp->sell_price,
                        tmp->bought, tmp->buy_price);
                broadcast_message(sess, buf);
        }
        broadcast_message(sess, "\n");
}

void auction(struct session *sess, const struct game_info *bank)
{
        struct player_bid *bids;
        int size = bank->active;
        if (!size)
                return;
        bids = malloc(size * sizeof(*bids));
        take_sell_offers(bids, sess);
        shuffle_offers(bids, size);
        qsort_offers(bids, size);
        prod_trade(bids, size, bank->prod_units);
        take_buy_offers(bids, sess);
        shuffle_offers(bids, size);
        qsort_offers(bids, size);
        raw_trade(bids, size, bank->raw_units);
        send_results(sess);
        free(bids);
}

void build_plants(struct session *ptr)
{
        char buf[128];
        int i, cost = ptr->build[0] * plant_price / 2;
        if (ptr->build[0]) {
                ptr->money -= cost;
                ptr->plants += ptr->build[0];
                sprintf(buf, "# Construction completed! Payment: $%d\n", cost);
                send_string(ptr, buf);
        }
        for (i = 0; i < month_plant_build - 1; i++)
                ptr->build[i] = ptr->build[i + 1];
        ptr->build[month_plant_build - 1] = 0;
}

void commit_transactions(struct session *ptr, struct session *sess,
                         struct game_info *bank)
{
        char buf[128];
        ptr->money -= ptr->produce * manufacture_price;
        ptr->raw -= ptr->produce;
        sprintf(buf, "# You've created %d prod units for $%d\n",
                ptr->produce, ptr->produce * manufacture_price);
        send_string(ptr, buf);
        ptr->money += ptr->sold * ptr->sell_price;
        ptr->prod -= ptr->sold;
        ptr->money -= ptr->prod * prod_storage_price;
        sprintf(buf, "# You've payed $%d for storing %d prod units\n",
                ptr->prod * prod_storage_price, ptr->prod);
        send_string(ptr, buf);
        ptr->money -= ptr->raw * raw_storage_price;
        sprintf(buf, "# You've payed $%d for storing %d raw units\n",
                ptr->raw * raw_storage_price, ptr->raw);
        send_string(ptr, buf);
        ptr->money -= ptr->bought * ptr->buy_price;
        ptr->raw += ptr->bought;
        ptr->prod += ptr->produce;
        ptr->money -= ptr->plants * maintain_plant_price;
        sprintf(buf, "# You've payed $%d for maintaining plants\n",
                ptr->plants * maintain_plant_price);
        send_string(ptr, buf);
        build_plants(ptr);
        sprintf(buf, "# Your balance is $%d\n\n", ptr->money);
        send_string(ptr, buf);
        if (ptr->money < 0) {
                ptr->flag = st_gameover;
                bank->active--;
                send_string(ptr, "$ You went bankrupt!\n\n");
                sprintf(buf, "$ Player #%d went bankrupt!\n\n", ptr->game_id);
                broadcast_message_except(sess, ptr, buf);
        }
}

void search_winner(struct session *sess)
{
        char buf[128];
        struct session *winner;
        for (winner = sess; winner; winner = winner->next) {
                if (winner->flag != st_gameover)
                        break;
        }
        if (winner) {
                send_string(winner, "$ Congratulations!!! You win!\n");
                sprintf(buf, "$ Player #%d wins the game!\n", winner->game_id);
                broadcast_message_except(sess, winner, buf);
        } else {
                broadcast_message(sess, "$ All players went bankrupt...\n");
        }
}

int change_level(int level)
{
        static const int distribution[5][5] = {
                { 4, 4, 2, 1, 1 },
                { 3, 4, 3, 1, 1 },
                { 1, 3, 4, 3, 1 },
                { 1, 1, 3, 4, 3 },
                { 1, 1, 2, 4, 4 }
        };
        int r = 1 + (int)(12.0 * rand() / (RAND_MAX + 1.0));
        int new_level = 0;
        while (r > 0 && new_level <= 5) {
                r -= distribution[level - 1][new_level];
                new_level++;
        }
        return new_level;
}

void market_conditions(struct game_info *bank)
{
        static const int parameters[5][4] = {
                { 2, 6, 800, 6500 },
                { 3, 5, 650, 6000 },
                { 4, 4, 500, 5500 },
                { 5, 3, 400, 5000 },
                { 6, 2, 300, 4500 }
        };
        bank->raw_units = parameters[bank->level - 1][0] * bank->active / 2;
        bank->prod_units = parameters[bank->level - 1][1] * bank->active / 2;
        bank->min_price = parameters[bank->level - 1][2];
        bank->max_price = parameters[bank->level - 1][3];
}

void init_game(struct game_info *bank, int count)
{
        bank->level = first_market_level;
        bank->month = 1;
        bank->active = count;
        bank->online = 0;
        bank->player_amount = count;
        bank->wait_players = 1;
        market_conditions(bank);
}

int is_thinking(struct session *sess)
{
        while (sess) {
                if (sess->flag == st_thinking)
                        return 1;
                sess = sess->next;
        }
        return 0;
}

void notify_game_started(struct session *sess)
{
        broadcast_message(sess,
                "# The game has started!\n"
                "# Type 'help' to get information\n\n"
        );
}

void next_month(struct session *sess)
{
        while (sess) {
                if (sess->flag == st_endturn)
                        sess->flag = st_thinking;
                clear_requests(sess);
                sess->sold = 0;
                sess->bought = 0;
                sess = sess->next;
        }
}

void game_process(struct session **sess, struct game_info *bank)
{
        struct session *tmp;
        if (bank->wait_players) {
                if (bank->online < bank->player_amount)
                        return;
                bank->wait_players = 0;
                notify_game_started(*sess);
        }
        if (is_thinking(*sess))
                return;
        auction(*sess, bank);
        for (tmp = *sess; tmp; tmp = tmp->next) {
                if (tmp->flag != st_gameover)
                        commit_transactions(tmp, *sess, bank);
        }
        if (bank->active > 1) {
                next_month(*sess);
                bank->month++;
                bank->level = change_level(bank->level);
                market_conditions(bank);
        } else {
                search_winner(*sess);
                delete_session_list(*sess);
                *sess = NULL;
                init_game(bank, bank->player_amount);
        }
}

const char *get_ip_address(struct sockaddr_in addr)
{
        return inet_ntoa(addr.sin_addr);
}

unsigned short get_port_number(struct sockaddr_in addr)
{
        return ntohs(addr.sin_port);
}

int get_game_id(struct session *sess, const struct game_info *bank)
{
        int id;
        char *is_available;
        is_available = malloc(bank->player_amount);
        for (id = 1; id <= bank->player_amount; id++)
                is_available[id - 1] = 1;
        while (sess) {
                is_available[sess->game_id - 1] = 0;
                sess = sess->next;
        }
        for (id = 1; id <= bank->player_amount; id++) {
                if (is_available[id - 1])
                        break;
        }
        free(is_available);
        return id;
}

void accept_connection(int ls, struct session **sess, struct game_info *bank)
{
        static const char msg[] = "Please, try again later...\n";
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(struct sockaddr_in);
        int sockfd, id;
        sockfd = accept(ls, (struct sockaddr *)&addr, &addrlen);
        if (sockfd == -1) {
                if (errno != EINTR)
                        perror("accept");
        } else {
                fprintf(stderr, "connection from %s:%u\n",
                        get_ip_address(addr), get_port_number(addr));
                if (bank->wait_players) {
                        id = get_game_id(*sess, bank);
                        create_session(sess, sockfd, id);
                        bank->online++;
                } else {
                        write(sockfd, msg, sizeof(msg) - 1);
                        shutdown(sockfd, 2);
                        close(sockfd);
                }
        }
}

void set_sigactions(sigset_t *orig_mask)
{
        struct sigaction sa;
        sigset_t mask;
        sa.sa_handler = SIG_IGN;
        sigfillset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGPIPE, &sa, NULL);
        sa.sa_handler = &signal_handler;
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGUSR1, &sa, NULL);
        sigaction(SIGUSR2, &sa, NULL);
        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGUSR1);
        sigaddset(&mask, SIGUSR2);
        sigprocmask(SIG_BLOCK, &mask, orig_mask);
}

void mainloop(int ls, int count)
{
        struct session *sess = NULL, *tmp;
        struct game_info bank;
        int res, max_d;
        fd_set readfds;
        sigset_t mask;
        set_sigactions(&mask);
        init_game(&bank, count);
        for (;;) {
                FD_ZERO(&readfds);
                FD_SET(ls, &readfds);
                max_d = ls;
                for (tmp = sess; tmp; tmp = tmp->next) {
                        FD_SET(tmp->socket_d, &readfds);
                        if (tmp->socket_d > max_d)
                                max_d = tmp->socket_d;
                }
                res = pselect(max_d + 1, &readfds, NULL, NULL, NULL, &mask);
                if (res == -1) {
                        if (errno != EINTR) {
                                perror("pselect");
                                exit(1);
                        }
                        if (sig_event_flag == sigev_terminate) {
                                delete_session_list(sess);
                                break;
                        }
                        if (sig_event_flag == sigev_restart) {
                                delete_session_list(sess);
                                sess = NULL;
                                init_game(&bank, count);
                                sig_event_flag = sigev_no_events;
                        }
                        continue;
                }
                if (FD_ISSET(ls, &readfds))
                        accept_connection(ls, &sess, &bank);
                for (tmp = sess; tmp; tmp = tmp->next) {
                        if (FD_ISSET(tmp->socket_d, &readfds))
                                read_data(tmp, sess, &bank);
                }
                bank.online -= delete_sessions(&sess);
                game_process(&sess, &bank);
        }
}

int init(const char *ipaddr, unsigned short port)
{
        int ls, res, opt = 1;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ipaddr);
        ls = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (ls == -1) {
                perror("socket");
                return -1;
        }
        res = setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (res == -1) {
                perror("setsockopt");
                return -1;
        }
        res = bind(ls, (struct sockaddr *)&addr, sizeof(addr));
        if (res == -1) {
                perror("bind");
                return -1;
        }
        res = listen(ls, 5);
        if (res == -1) {
                perror("listen");
                return -1;
        }
        return ls;
}

int main(int argc, char **argv)
{
        int ls, count;
        if (argc != 4) {
                fputs("Usage: server [ip] [port] [players]\n", stderr);
                exit(1);
        }
        count = atoi(argv[3]);
        if (count <= 0) {
                fputs("Invalid player amount\n", stderr);
                exit(1);
        }
        ls = init(argv[1], atoi(argv[2]));
        if (ls == -1) {
                fputs("Failed to bring server up\n", stderr);
                exit(1);
        }
        srand(time(NULL));
        fputs("server is running\n", stderr);
        mainloop(ls, count);
        shutdown(ls, 2);
        close(ls);
        fputs("server is stopped\n", stderr);
        return 0;
}

