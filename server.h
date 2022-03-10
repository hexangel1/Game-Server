#ifndef SERVER_H_SENTRY
#define SERVER_H_SENTRY

#define INBUFSIZE 1024

enum signal_events {
        sigev_no_events = 0,
        sigev_terminate = 1,
        sigev_restart   = 2
};

enum game_constants {
        first_market_level   = 3,
        money_starter_kit    = 10000,
        raw_starter_kit      = 4,
        prod_starter_kit     = 2,
        plants_starter_kit   = 2,
        plant_price          = 5000,
        manufacture_price    = 2000,
        maintain_plant_price = 1000,
        prod_storage_price   = 500,
        raw_storage_price    = 300,
        month_plant_build    = 5
};

enum game_command {
        cmd_empty,
        cmd_market,
        cmd_info,
        cmd_sell,
        cmd_buy,
        cmd_prod,
        cmd_build,
        cmd_cancel,
        cmd_turn,
        cmd_view,
        cmd_help,
        cmd_error
};

enum fsm_state {
        st_thinking,
        st_endturn,
        st_gameover,
        st_goodbye
};

struct game_request {
        enum game_command cmd;
        int argv[2];
};

struct player_bid {
        int count;
        int price;
        struct session *player;
};

struct game_info {
        int raw_units;
        int prod_units;
        int min_price;
        int max_price;
        int level;
        int month;
        int active;
        int online;
        int player_amount;
        int wait_players;
};

struct session {
        int socket_d;
        int buf_used;
        char buf[INBUFSIZE];
        enum fsm_state flag;
        int game_id;
        int money;
        int raw;
        int prod;
        int plants;
        int build[month_plant_build];
        int sell_price;
        int sell_count;
        int buy_price;
        int buy_count;
        int produce;
        int sold;
        int bought;
        struct session *next;
};

#endif /* SERVER_H_SENTRY */

