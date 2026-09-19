/* Delivery-channel prior, extracted verbatim from hlse_core.c. */
#include "hlse_channel.h"
#include <string.h>

static const char *g_from_channel = NULL;   /* NULL when --from absent */

void        hlse_set_from_channel(const char *ch) { g_from_channel = ch; }
const char *hlse_from_channel(void)               { return g_from_channel; }

int
hlse_channel_delta(const char *ch)
{
    if (!ch) return 0;
    if (strcmp(ch, "qr")     == 0) return 20; /* quishing — QR masks destination */
    if (strcmp(ch, "sms")    == 0) return 15; /* smishing — primary mobile vector  */
    if (strcmp(ch, "email")  == 0) return 10; /* phishing — classic email vector   */
    if (strcmp(ch, "dm")     == 0) return 10; /* social-engineering via DM         */
    if (strcmp(ch, "manual") == 0) return  0; /* user typed it — lowest prior      */
    return 0;
}

const char *
hlse_channel_reason(const char *ch)
{
    if (!ch) return NULL;
    if (strcmp(ch, "qr")    == 0)
        return "Channel (qr): +20 \xe2\x80\x94 QR codes mask destinations (quishing)";
    if (strcmp(ch, "sms")   == 0)
        return "Channel (sms): +15 \xe2\x80\x94 SMS is the primary smishing "
               "vector; on RCS the displayed sender name is set by the sender, "
               "so a familiar brand or carrier label is NOT proof of identity";
    if (strcmp(ch, "email") == 0)
        return "Channel (email): +10 \xe2\x80\x94 email is the primary phishing vector";
    if (strcmp(ch, "dm")    == 0)
        return "Channel (dm): +10 \xe2\x80\x94 direct messages are used for social-engineering";
    return NULL; /* manual → no delta, no noise */
}
