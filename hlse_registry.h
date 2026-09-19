/* hlse_registry.h — the stable HLSE-* pattern_id registry printer.
 * CLI-only (--list-patterns); emits the append-only routing table SIEM/
 * SOAR consumers key on. Returns 0. */
#ifndef HLSE_REGISTRY_H
#define HLSE_REGISTRY_H

int hlse_list_patterns(int json_out);

#endif /* HLSE_REGISTRY_H */
