#include <lwjson.h>
#include <jsmn.h>
#include <unity.h>
#include <string.h>

static const char *JSON_STRING = 
    "{\"user\": \"johndoe\", \"admin\": false, \"uid\": 1000,\n  "
    "\"groups\": [\"users\", \"wheel\", \"audio\", \"video\"]}";

static lwjson_token_t tokens[128];
static lwjson_t lwjson;

void setUp(void)
{
  // set stuff up here
}

void tearDown(void)
{
  // clean stuff up here
}

void test_function_minimal_lwjson(void) {
    lwjson_init(&lwjson, tokens, LWJSON_ARRAYSIZE(tokens));
    if (lwjson_parse(&lwjson, JSON_STRING) == lwjsonOK) {
        const lwjson_token_t* t;
        // printf("JSON parsed..\r\n");

        /* Find custom key in JSON */
        if ((t = lwjson_find(&lwjson, "groups")) != NULL) {
            TEST_ASSERT_EQUAL_INT(LWJSON_TYPE_ARRAY, t->type);
        }

        /* Call this when not used anymore */
        lwjson_free(&lwjson);
    }
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

void test_function_jsmn_simple_json(void)
{
    char* groups[] = {"users", "wheel", "audio", "video"};
    int counter = 0;
    int i;
    int r;
    jsmn_parser p;
    jsmntok_t t[128]; /* We expect no more than 128 tokens */
    jsmn_init(&p);
    r = jsmn_parse(&p, JSON_STRING, strlen(JSON_STRING), t,
                sizeof(t) / sizeof(t[0]));
    TEST_ASSERT_GREATER_THAN(0, r);

    for (i = 1; i < r; i++) {
        if (jsoneq(JSON_STRING, &t[i], "user") == 0) {
            TEST_ASSERT_EQUAL_STRING("johndoe", strndup(JSON_STRING + t[i + 1].start, t[i + 1].end - t[i + 1].start));
            i++;
        } else if (jsoneq(JSON_STRING, &t[i], "admin") == 0) {
            TEST_ASSERT_EQUAL_STRING("false", strndup(JSON_STRING + t[i + 1].start, t[i + 1].end - t[i + 1].start));
            i++;
        } else if (jsoneq(JSON_STRING, &t[i], "uid") == 0) {
            TEST_ASSERT_EQUAL_STRING("1000", strndup(JSON_STRING + t[i + 1].start, t[i + 1].end - t[i + 1].start));
            i++;
        } else if (jsoneq(JSON_STRING, &t[i], "groups") == 0) {
            int j;
            if (t[i + 1].type != JSMN_ARRAY) {
                continue; /* We expect groups to be an array of strings */
            }
            for (j = 0; j < t[i + 1].size; j++) {
                jsmntok_t *g = &t[i + j + 2];
                TEST_ASSERT_EQUAL_STRING(groups[counter], strndup(JSON_STRING + g->start, g->end - g->start));
                counter += 1;
            }
            i += t[i + 1].size + 1;
        } else {
            TEST_ASSERT_GREATER_THAN(0, r);
        }
    }
}

void app_main()
{
    UNITY_BEGIN();

    RUN_TEST(test_function_minimal_lwjson);
    RUN_TEST(test_function_jsmn_simple_json);

    UNITY_END();
}