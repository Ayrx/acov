const module_map = new ModuleMap();

interface ModuleOffset {
    name: string,
    offset: string,
}

function get_module_offset(address: NativePointer) : ModuleOffset | undefined {
    var m = module_map.find(address);
    if (m == null) {
        console.error("[-] Unable to find module belonging to addr: " + address);
        return;
    }

    return { name: m.name, offset: address.sub(m.base).toString() };
}

for (var thread of Process.enumerateThreads()) {
    Stalker.follow(thread.id, {
        events: {
            compile: true
        },
        onReceive: function(events) {
            const bb_events = Stalker.parse(events, {
                annotate: false,
                stringify: false,
            });

            for (var bb of bb_events) {
                const m = get_module_offset(bb[0] as NativePointer);

                if (m != undefined) {
                    send({
                        "module": m.name,
                        "offset": m.offset,
                        "tid": thread.id
                    });
                }
            }
        }
    });
}
