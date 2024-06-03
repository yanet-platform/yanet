#include <rte_mbuf.h>

#include "globalbase.h"
#include "icmp.h"

namespace dataplane
{
bool do_icmp_translate_v6_to_v4(rte_mbuf* mbuf,
                                const dataplane::globalBase::nat64stateless_translation_t& translation);
bool do_icmp_translate_v4_to_v6(rte_mbuf* mbuf,
                                const dataplane::globalBase::nat64stateless_translation_t& translation);

} // namespace dataplane