/* hlse_channel.h — delivery-channel threat prior (--from / config `from`).
 *
 * Socratic Q: "You analysed the URL — but HLSE has no idea how it reached
 * you.  A QR code in a parking meter and a link you typed yourself share
 * the same bytes, yet carry very different priors.  Should the channel
 * change the verdict?"  Answer: yes — the channel is a threat-prior.
 *
 * The global is set once at CLI startup (hlse_set_from_channel) and read
 * by the output printers via hlse_from_channel(). */
#ifndef HLSE_CHANNEL_H
#define HLSE_CHANNEL_H

void        hlse_set_from_channel(const char *ch);
const char *hlse_from_channel(void);

/* Score boost for URLs on a high-risk channel (capped at 100 at the
 * output sites). Meaningful for URLs; text applies its own handling. */
int         hlse_channel_delta(const char *ch);
/* Reason string for the boost (NULL when delta==0). */
const char *hlse_channel_reason(const char *ch);

#endif /* HLSE_CHANNEL_H */
