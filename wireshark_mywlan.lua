-- `wireshark -X lua_script:./wireshark_mywlan.lua`
-- if dumpcap2udp is used with a monitor interface
-- iw wlan0 interface add mon0 type monitor
-- ip link set mon0 up
-- dumpcap2udp -T 172.23.42.222 -s 256 -i mon0 ""
-- dont forget the "", there is still a bug in dumpcap2udp
mywlan = Proto("mywlan", "My WLAN")

function mywlan.dissector(buffer, pinfo, tree)
    local radiotap = Dissector.get("radiotap")
    radiotap:call(buffer, pinfo, tree)
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(3999, mywlan)
