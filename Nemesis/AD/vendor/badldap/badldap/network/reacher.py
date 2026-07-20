from badldap import logger as LOG
import ssl, asyncio, collections
from dns import resolver, rdatatype

async def host_connect(ip, port):
    # Even if a dc doesn't support tls with ldap/gc it will accept the tcp connection
    # so we start a tls handshake on those port to be sure it handles tls
    ssl_context = None
    if port in [636, 3269]:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    try:
        LOG.debug(f"Attempting to TCP connect to {ip}:{port}")
        reader, writer = await asyncio.open_connection(ip, port, ssl=ssl_context)
        writer.close()
        await writer.wait_closed()
        return {"ip": ip, "port": port}
    except:
        LOG.debug(f"Could not TCP connect to {ip}:{port}")
        return {}


async def wait_first(tasks):
    while tasks:
        finished, unfinished = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
        for x in finished:
            result = x.result()
            if result:
                if unfinished:
                    # cancel the other tasks, we have a result. We need to wait for the cancellations
                    # to propagate.
                    LOG.debug(f"Cancelling {len(unfinished)} remaining tasks")
                    for task in unfinished:
                        task.cancel()
                    await asyncio.wait(unfinished)
                return result
        tasks = unfinished
    return


# Try to reach a host by first resolving its IPv4 or v6 by providing a nameserver and SRV, A or AAAA records
# Then trying to do a tcp connect on all hosts found, first answering will be returned
async def asyncResolveAndConnect(ns, r, ports):
    custom_resolver = resolver.Resolver()
    custom_resolver.nameservers = [ns]
    custom_resolver.timeout = 600
    custom_resolver.lifetime = 600
    target_srvs = collections.defaultdict(list)
    answer = None
    LOG.debug(f"Resolving {r}...")
    for rtype in r["type"]:
        try:
            answer = custom_resolver.resolve(r["name"], rtype, tcp=True)
            # SRV records
            if answer.rdtype == rdatatype.SRV:
                # Try to get IPs from additional part of the answer if there is one
                for raddi in answer.response.additional:
                    if raddi.rdtype in [rdatatype.A, rdatatype.AAAA]:
                        for raddr in raddi:
                            target_srvs[str(raddi.name)].append(raddr.address)
                # If no additional part we have to make other queries
                if not target_srvs:
                    for rsrv in answer:
                        for rsrv_type in ["A", "AAAA"]:
                            try:
                                target_srvs[rsrv.target.to_text()] += [
                                    rdata.address
                                    for rdata in custom_resolver.resolve(
                                        rsrv.target.to_text(), rsrv_type, tcp=True
                                    )
                                ]
                            except Exception as e:
                                LOG.debug(
                                    f"Failed to resolve {rsrv.target.to_text()} {rsrv_type} with nameserver {ns}: {e}"
                                )
                                continue
            # A and AAAA records
            else:
                target_srvs[r["name"]] += [raddr.address for raddr in answer]

        except Exception as e:
            LOG.debug(
                f"Failed to resolve {r['name']} {rtype} with nameserver {ns}: {e}"
            )
            continue

    # If the function failed to find hosts
    if not target_srvs:
        return {}

    # We try every combination of ips/ports, useful if there are firewalls
    # And we take the first to answer, we need only one having the replicas we need
    connect_tasks = []
    for port in ports:
        for target_ips in target_srvs.values():
            for ip in target_ips:
                connect_tasks.append(asyncio.create_task(host_connect(ip, port)))

    host_params = await wait_first(connect_tasks)
    # Function couldn't reach a host for this record
    if not host_params:
        return {}

    for name, ips in target_srvs.items():
        if host_params["ip"] in ips:
            if name.endswith("."):
                name = name.rstrip(".")
            host_params["name"] = name
            break
    return host_params


# Do 389 even for GC because more probabilities to bypass fw
# 389 LDAP, 636 LDAPS, 3268 GC, 3269 GCS
async def findReachableServer(
    record_list, dns_addr="", dc_dns="", ports=None
):
    if ports is None:
        ports = [389, 636, 3268, 3269]
    nameservers = [] + (resolver.get_default_resolver()).nameservers
    if dc_dns:
        nameservers = [dc_dns] + nameservers
    if dns_addr:
        nameservers = [dns_addr] + nameservers
    LOG.debug(f"Nameservers set to: {nameservers}")

    # Try to find a dc where we can connect asap
    resolve_tasks = []
    for ns in nameservers:
        for r in record_list:
            resolve_tasks.append(
                asyncio.create_task(asyncResolveAndConnect(ns, r, ports))
            )

    host_params = await wait_first(resolve_tasks)
    return host_params


# Find LDAP or GC server based on current AD site
async def findReachableDomainServer(
    domain_or_forest_name, ad_site, server_type="", dns_addr="", dc_dns=""
):
    record_list = []
    ports = []
    if not server_type or server_type == "gc":
        record_list += [
            {
                "type": ["SRV"],
                "name": f"_gc._tcp.{ad_site}._sites.{domain_or_forest_name}",
            },
            {"type": ["SRV"], "name": f"_gc._tcp.{domain_or_forest_name}"},
        ]
        ports += [3268, 3269]
    if not server_type or server_type == "ldap":
        record_list += [
            {
                "type": ["SRV"],
                "name": f"_ldap._tcp.{ad_site}._sites.{domain_or_forest_name}",
            },
            {"type": ["SRV"], "name": f"_ldap._tcp.{domain_or_forest_name}"},
        ]
        ports += [389, 636]
    host_params = await findReachableServer(record_list, dns_addr, dc_dns, ports)
    return host_params