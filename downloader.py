import webbrowser
import time

raw_filenames = """
mypcap_20091103082335.pcap.xz
mypcap_20091103082443.pcap.xz
mypcap_20091103082550.pcap.xz
mypcap_20091103082655.pcap.xz
mypcap_20091103082759.pcap.xz
mypcap_20091103082902.pcap.xz
mypcap_20091103083006.pcap.xz
mypcap_20091103083107.pcap.xz
mypcap_20091103083207.pcap.xz
mypcap_20091103083310.pcap.xz
mypcap_20091103083412.pcap.xz
mypcap_20091103083512.pcap.xz
mypcap_20091103083612.pcap.xz
mypcap_20091103083710.pcap.xz
mypcap_20091103083808.pcap.xz
mypcap_20091103083906.pcap.xz
mypcap_20091103084002.pcap.xz
mypcap_20091103084058.pcap.xz
mypcap_20091103084154.pcap.xz
mypcap_20091103084249.pcap.xz
mypcap_20091103084347.pcap.xz
mypcap_20091103084443.pcap.xz
mypcap_20091103084538.pcap.xz
mypcap_20091103084634.pcap.xz
mypcap_20091103084727.pcap.xz
mypcap_20091103084818.pcap.xz
mypcap_20091103084909.pcap.xz
mypcap_20091103085002.pcap.xz
mypcap_20091103085056.pcap.xz
mypcap_20091103085148.pcap.xz
mypcap_20091103085237.pcap.xz
mypcap_20091103085326.pcap.xz
mypcap_20091103085417.pcap.xz
mypcap_20091103085503.pcap.xz
mypcap_20091103085553.pcap.xz
mypcap_20091103085642.pcap.xz
mypcap_20091103085734.pcap.xz
mypcap_20091103085823.pcap.xz
mypcap_20091103085911.pcap.xz
mypcap_20091103090001.pcap.xz
mypcap_20091103090049.pcap.xz
mypcap_20091103090139.pcap.xz
mypcap_20091103090229.pcap.xz
mypcap_20091103090319.pcap.xz
mypcap_20091103090407.pcap.xz
mypcap_20091103090456.pcap.xz
mypcap_20091103090542.pcap.xz
mypcap_20091103090631.pcap.xz
mypcap_20091103090719.pcap.xz
mypcap_20091103090808.pcap.xz
mypcap_20091103090857.pcap.xz
mypcap_20091103090958.pcap.xz
mypcap_20091103091059.pcap.xz
mypcap_20091103091147.pcap.xz
mypcap_20091103091238.pcap.xz
mypcap_20091103091327.pcap.xz
mypcap_20091103091417.pcap.xz
mypcap_20091103091506.pcap.xz
mypcap_20091103091556.pcap.xz
mypcap_20091103091642.pcap.xz
mypcap_20091103091730.pcap.xz
mypcap_20091103091818.pcap.xz
mypcap_20091103091905.pcap.xz
mypcap_20091103091950.pcap.xz
mypcap_20091103092037.pcap.xz
mypcap_20091103092121.pcap.xz
mypcap_20091103092207.pcap.xz
mypcap_20091103092253.pcap.xz
mypcap_20091103092338.pcap.xz
mypcap_20091103092426.pcap.xz
mypcap_20091103092514.pcap.xz
mypcap_20091103092603.pcap.xz
mypcap_20091103092648.pcap.xz
mypcap_20091103092735.pcap.xz
mypcap_20091103092821.pcap.xz
mypcap_20091103092907.pcap.xz
mypcap_20091103092952.pcap.xz
mypcap_20091103093040.pcap.xz
mypcap_20091103093127.pcap.xz
mypcap_20091103093215.pcap.xz
mypcap_20091103093304.pcap.xz
mypcap_20091103093352.pcap.xz
mypcap_20091103093438.pcap.xz
mypcap_20091103093525.pcap.xz
mypcap_20091103093611.pcap.xz
mypcap_20091103093701.pcap.xz
mypcap_20091103093747.pcap.xz
mypcap_20091103093835.pcap.xz
mypcap_20091103093922.pcap.xz
mypcap_20091103094014.pcap.xz
mypcap_20091103094212.pcap.xz
mypcap_20091103094257.pcap.xz
mypcap_20091103094343.pcap.xz
mypcap_20091103094429.pcap.xz
mypcap_20091103094516.pcap.xz
mypcap_20091103094602.pcap.xz
mypcap_20091103094647.pcap.xz
mypcap_20091103094734.pcap.xz
mypcap_20091103094821.pcap.xz
mypcap_20091103094908.pcap.xz
mypcap_20091103094953.pcap.xz
mypcap_20091103095038.pcap.xz
mypcap_20091103095125.pcap.xz
mypcap_20091103095211.pcap.xz
mypcap_20091103095256.pcap.xz
mypcap_20091103095342.pcap.xz
mypcap_20091103095427.pcap.xz
mypcap_20091103095513.pcap.xz
mypcap_20091103095601.pcap.xz
mypcap_20091103095649.pcap.xz
mypcap_20091103095735.pcap.xz
mypcap_20091103095822.pcap.xz
mypcap_20091103095906.pcap.xz
mypcap_20091103095954.pcap.xz
mypcap_20091103100042.pcap.xz
mypcap_20091103100130.pcap.xz
mypcap_20091103100218.pcap.xz
mypcap_20091103100307.pcap.xz
mypcap_20091103100359.pcap.xz
mypcap_20091103100447.pcap.xz
mypcap_20091103100534.pcap.xz
mypcap_20091103100618.pcap.xz
mypcap_20091103100705.pcap.xz
mypcap_20091103100751.pcap.xz
mypcap_20091103100838.pcap.xz
mypcap_20091103100926.pcap.xz
mypcap_20091103101013.pcap.xz
mypcap_20091103101059.pcap.xz
mypcap_20091103101148.pcap.xz
mypcap_20091103101238.pcap.xz
mypcap_20091103101324.pcap.xz
mypcap_20091103101411.pcap.xz
mypcap_20091103101501.pcap.xz
mypcap_20091103101548.pcap.xz
mypcap_20091103101636.pcap.xz
mypcap_20091103101722.pcap.xz
mypcap_20091103101809.pcap.xz
mypcap_20091103101856.pcap.xz
mypcap_20091103101941.pcap.xz
mypcap_20091103102028.pcap.xz
mypcap_20091103102115.pcap.xz
mypcap_20091103102203.pcap.xz
mypcap_20091103102252.pcap.xz
mypcap_20091103102339.pcap.xz
mypcap_20091103102429.pcap.xz
mypcap_20091103102515.pcap.xz
mypcap_20091103102602.pcap.xz
mypcap_20091103102652.pcap.xz
mypcap_20091103102742.pcap.xz
mypcap_20091103102831.pcap.xz
mypcap_20091103102919.pcap.xz
mypcap_20091103103007.pcap.xz
mypcap_20091103103055.pcap.xz
mypcap_20091103103145.pcap.xz
mypcap_20091103103232.pcap.xz
mypcap_20091103103321.pcap.xz
mypcap_20091103103412.pcap.xz
mypcap_20091103103500.pcap.xz
mypcap_20091103103548.pcap.xz
mypcap_20091103103637.pcap.xz
mypcap_20091103103728.pcap.xz
mypcap_20091103103819.pcap.xz
mypcap_20091103103909.pcap.xz
mypcap_20091103103957.pcap.xz
mypcap_20091103104048.pcap.xz
mypcap_20091103104137.pcap.xz
mypcap_20091103104224.pcap.xz
mypcap_20091103104313.pcap.xz
mypcap_20091103104404.pcap.xz
mypcap_20091103104454.pcap.xz
mypcap_20091103104544.pcap.xz
mypcap_20091103104634.pcap.xz
mypcap_20091103104724.pcap.xz
mypcap_20091103104814.pcap.xz
mypcap_20091103104908.pcap.xz
mypcap_20091103104957.pcap.xz
mypcap_20091103105050.pcap.xz
mypcap_20091103105141.pcap.xz
mypcap_20091103105232.pcap.xz
mypcap_20091103105327.pcap.xz
mypcap_20091103105422.pcap.xz
mypcap_20091103105515.pcap.xz
mypcap_20091103105609.pcap.xz
mypcap_20091103105703.pcap.xz
mypcap_20091103105755.pcap.xz
mypcap_20091103105847.pcap.xz
mypcap_20091103105938.pcap.xz
mypcap_20091103110030.pcap.xz
mypcap_20091103110123.pcap.xz
mypcap_20091103110219.pcap.xz
mypcap_20091103110312.pcap.xz
mypcap_20091103110406.pcap.xz
mypcap_20091103110459.pcap.xz
mypcap_20091103110553.pcap.xz
mypcap_20091103110645.pcap.xz
mypcap_20091103110741.pcap.xz
mypcap_20091103110838.pcap.xz
mypcap_20091103110933.pcap.xz
mypcap_20091103111026.pcap.xz
mypcap_20091103111122.pcap.xz
mypcap_20091103111243.pcap.xz
mypcap_20091103111337.pcap.xz
mypcap_20091103111432.pcap.xz
mypcap_20091103111529.pcap.xz
mypcap_20091103111623.pcap.xz
mypcap_20091103111720.pcap.xz
mypcap_20091103111816.pcap.xz
mypcap_20091103111908.pcap.xz
mypcap_20091103112002.pcap.xz
mypcap_20091103112059.pcap.xz
mypcap_20091103112157.pcap.xz
mypcap_20091103112253.pcap.xz
mypcap_20091103112349.pcap.xz
mypcap_20091103112448.pcap.xz
mypcap_20091103112547.pcap.xz
mypcap_20091103112648.pcap.xz
mypcap_20091103112747.pcap.xz
mypcap_20091103112848.pcap.xz
mypcap_20091103112946.pcap.xz
mypcap_20091103113043.pcap.xz
mypcap_20091103113145.pcap.xz
mypcap_20091103113241.pcap.xz
mypcap_20091103113340.pcap.xz
mypcap_20091103113439.pcap.xz
mypcap_20091103113539.pcap.xz
mypcap_20091103113637.pcap.xz
mypcap_20091103113738.pcap.xz
mypcap_20091103113834.pcap.xz
mypcap_20091103113932.pcap.xz
mypcap_20091103114030.pcap.xz
mypcap_20091103114128.pcap.xz
mypcap_20091103114225.pcap.xz
mypcap_20091103114324.pcap.xz
mypcap_20091103114420.pcap.xz
mypcap_20091103114520.pcap.xz
mypcap_20091103114619.pcap.xz
mypcap_20091103114720.pcap.xz
mypcap_20091103114818.pcap.xz
mypcap_20091103114917.pcap.xz
mypcap_20091103115013.pcap.xz
mypcap_20091103115113.pcap.xz
mypcap_20091103115212.pcap.xz
mypcap_20091103115313.pcap.xz
mypcap_20091103115411.pcap.xz
mypcap_20091103115509.pcap.xz
mypcap_20091103115606.pcap.xz
mypcap_20091103115703.pcap.xz
mypcap_20091103115802.pcap.xz
mypcap_20091103115904.pcap.xz
mypcap_20091103120003.pcap.xz
mypcap_20091103120059.pcap.xz
mypcap_20091103120157.pcap.xz
mypcap_20091103120255.pcap.xz
mypcap_20091103120352.pcap.xz
mypcap_20091103120447.pcap.xz
mypcap_20091103120547.pcap.xz
mypcap_20091103120643.pcap.xz
mypcap_20091103120739.pcap.xz
mypcap_20091103120833.pcap.xz
mypcap_20091103120929.pcap.xz
mypcap_20091103121027.pcap.xz
mypcap_20091103121124.pcap.xz
mypcap_20091103121221.pcap.xz
mypcap_20091103121317.pcap.xz
mypcap_20091103121413.pcap.xz
mypcap_20091103121511.pcap.xz
mypcap_20091103121607.pcap.xz
mypcap_20091103121700.pcap.xz
mypcap_20091103121754.pcap.xz
mypcap_20091103121848.pcap.xz
mypcap_20091103121942.pcap.xz
mypcap_20091103122035.pcap.xz
mypcap_20091103122131.pcap.xz
mypcap_20091103122222.pcap.xz
mypcap_20091103122314.pcap.xz
mypcap_20091103122407.pcap.xz
mypcap_20091103122504.pcap.xz
mypcap_20091103122601.pcap.xz
mypcap_20091103122653.pcap.xz
mypcap_20091103122746.pcap.xz
mypcap_20091103122841.pcap.xz
mypcap_20091103122934.pcap.xz
mypcap_20091103123026.pcap.xz
mypcap_20091103123118.pcap.xz
mypcap_20091103123212.pcap.xz
mypcap_20091103123304.pcap.xz
mypcap_20091103123356.pcap.xz
mypcap_20091103123448.pcap.xz
mypcap_20091103123540.pcap.xz
mypcap_20091103123631.pcap.xz
mypcap_20091103123723.pcap.xz
mypcap_20091103123814.pcap.xz
mypcap_20091103123906.pcap.xz
mypcap_20091103123956.pcap.xz
mypcap_20091103124048.pcap.xz
mypcap_20091103124142.pcap.xz
mypcap_20091103124233.pcap.xz
mypcap_20091103124327.pcap.xz
mypcap_20091103124418.pcap.xz
mypcap_20091103124508.pcap.xz
mypcap_20091103124559.pcap.xz
mypcap_20091103124649.pcap.xz
mypcap_20091103124740.pcap.xz
mypcap_20091103124832.pcap.xz
mypcap_20091103124921.pcap.xz
mypcap_20091103125011.pcap.xz
mypcap_20091103125100.pcap.xz
mypcap_20091103125150.pcap.xz
mypcap_20091103125243.pcap.xz
mypcap_20091103125333.pcap.xz
mypcap_20091103125424.pcap.xz
mypcap_20091103125514.pcap.xz
mypcap_20091103125605.pcap.xz
mypcap_20091103125655.pcap.xz
mypcap_20091103125744.pcap.xz
mypcap_20091103125832.pcap.xz
mypcap_20091103125921.pcap.xz
mypcap_20091103130012.pcap.xz
mypcap_20091103130102.pcap.xz
mypcap_20091103130152.pcap.xz
mypcap_20091103130241.pcap.xz
mypcap_20091103130331.pcap.xz
mypcap_20091103130422.pcap.xz
mypcap_20091103130512.pcap.xz
mypcap_20091103130601.pcap.xz
mypcap_20091103130648.pcap.xz
mypcap_20091103130738.pcap.xz
mypcap_20091103130827.pcap.xz
mypcap_20091103130918.pcap.xz
mypcap_20091103131004.pcap.xz
mypcap_20091103131055.pcap.xz
mypcap_20091103131146.pcap.xz
mypcap_20091103131234.pcap.xz
mypcap_20091103131322.pcap.xz
mypcap_20091103131412.pcap.xz
mypcap_20091103131500.pcap.xz
mypcap_20091103131547.pcap.xz
mypcap_20091103131637.pcap.xz
mypcap_20091103131727.pcap.xz
mypcap_20091103131816.pcap.xz
mypcap_20091103131904.pcap.xz
mypcap_20091103131953.pcap.xz
mypcap_20091103132039.pcap.xz
mypcap_20091103132129.pcap.xz
mypcap_20091103132218.pcap.xz
mypcap_20091103132307.pcap.xz
mypcap_20091103132356.pcap.xz
mypcap_20091103132445.pcap.xz
mypcap_20091103132535.pcap.xz
mypcap_20091103132624.pcap.xz
mypcap_20091103132714.pcap.xz
mypcap_20091103132804.pcap.xz
mypcap_20091103132853.pcap.xz
mypcap_20091103132941.pcap.xz
mypcap_20091103133029.pcap.xz
mypcap_20091103133119.pcap.xz
mypcap_20091103133207.pcap.xz
mypcap_20091103133256.pcap.xz
mypcap_20091103133345.pcap.xz
mypcap_20091103133435.pcap.xz
mypcap_20091103133522.pcap.xz
mypcap_20091103133610.pcap.xz
mypcap_20091103133659.pcap.xz
mypcap_20091103133749.pcap.xz
mypcap_20091103133839.pcap.xz
mypcap_20091103133927.pcap.xz
mypcap_20091103134015.pcap.xz
mypcap_20091103134104.pcap.xz
mypcap_20091103134151.pcap.xz
mypcap_20091103134241.pcap.xz
mypcap_20091103134333.pcap.xz
mypcap_20091103134422.pcap.xz
mypcap_20091103134509.pcap.xz
mypcap_20091103134559.pcap.xz
mypcap_20091103134650.pcap.xz
mypcap_20091103134737.pcap.xz
mypcap_20091103134824.pcap.xz
mypcap_20091103134911.pcap.xz
mypcap_20091103135001.pcap.xz
mypcap_20091103135049.pcap.xz
mypcap_20091103135139.pcap.xz
mypcap_20091103135225.pcap.xz
mypcap_20091103135315.pcap.xz
mypcap_20091103135403.pcap.xz
mypcap_20091103135451.pcap.xz
mypcap_20091103135542.pcap.xz
mypcap_20091103135633.pcap.xz
mypcap_20091103135720.pcap.xz
mypcap_20091103135808.pcap.xz
mypcap_20091103135857.pcap.xz
mypcap_20091103135946.pcap.xz
mypcap_20091103140033.pcap.xz
mypcap_20091103140121.pcap.xz
mypcap_20091103140210.pcap.xz
mypcap_20091103140259.pcap.xz
mypcap_20091103140349.pcap.xz
mypcap_20091103140437.pcap.xz
mypcap_20091103140527.pcap.xz
mypcap_20091103140615.pcap.xz
mypcap_20091103140705.pcap.xz
mypcap_20091103140756.pcap.xz
mypcap_20091103140845.pcap.xz
mypcap_20091103140934.pcap.xz
mypcap_20091103141022.pcap.xz
mypcap_20091103141111.pcap.xz
mypcap_20091103141200.pcap.xz
mypcap_20091103141249.pcap.xz
mypcap_20091103141339.pcap.xz
mypcap_20091103141430.pcap.xz
mypcap_20091103141521.pcap.xz
mypcap_20091103141610.pcap.xz
mypcap_20091103141701.pcap.xz
mypcap_20091103141749.pcap.xz
mypcap_20091103141841.pcap.xz
mypcap_20091103141933.pcap.xz
mypcap_20091103142023.pcap.xz
mypcap_20091103142115.pcap.xz
mypcap_20091103142205.pcap.xz
mypcap_20091103142253.pcap.xz
mypcap_20091103142344.pcap.xz
mypcap_20091103142436.pcap.xz
mypcap_20091103142528.pcap.xz
mypcap_20091103142617.pcap.xz
mypcap_20091103142706.pcap.xz
mypcap_20091103142756.pcap.xz
mypcap_20091103142847.pcap.xz
mypcap_20091103142940.pcap.xz
mypcap_20091103143031.pcap.xz
mypcap_20091103143124.pcap.xz
mypcap_20091103143216.pcap.xz
mypcap_20091103143307.pcap.xz
mypcap_20091103143359.pcap.xz
mypcap_20091103143451.pcap.xz
mypcap_20091103143545.pcap.xz
mypcap_20091103143639.pcap.xz
mypcap_20091103143732.pcap.xz
mypcap_20091103143826.pcap.xz
mypcap_20091103143920.pcap.xz
mypcap_20091103144014.pcap.xz
mypcap_20091103144108.pcap.xz
mypcap_20091103144203.pcap.xz
mypcap_20091103144259.pcap.xz
mypcap_20091103144354.pcap.xz
mypcap_20091103144450.pcap.xz
mypcap_20091103144546.pcap.xz
mypcap_20091103144640.pcap.xz
mypcap_20091103144736.pcap.xz
mypcap_20091103144833.pcap.xz
mypcap_20091103144926.pcap.xz
mypcap_20091103145023.pcap.xz
mypcap_20091103145120.pcap.xz
mypcap_20091103145316.pcap.xz
mypcap_20091103145412.pcap.xz
mypcap_20091103145510.pcap.xz
mypcap_20091103145612.pcap.xz
mypcap_20091103145707.pcap.xz
mypcap_20091103145808.pcap.xz
mypcap_20091103145907.pcap.xz
mypcap_20091103150006.pcap.xz
mypcap_20091103150106.pcap.xz
mypcap_20091103150207.pcap.xz
mypcap_20091103150309.pcap.xz
mypcap_20091103150409.pcap.xz
mypcap_20091103150511.pcap.xz
mypcap_20091103150614.pcap.xz
mypcap_20091103150718.pcap.xz
mypcap_20091103150823.pcap.xz
mypcap_20091103150926.pcap.xz
mypcap_20091103151030.pcap.xz
mypcap_20091103151138.pcap.xz
mypcap_20091103151245.pcap.xz
mypcap_20091103151356.pcap.xz
mypcap_20091103151507.pcap.xz
mypcap_20091103151617.pcap.xz
mypcap_20091103151726.pcap.xz
mypcap_20091103151837.pcap.xz
mypcap_20091103151946.pcap.xz
mypcap_20091103152100.pcap.xz
mypcap_20091103152215.pcap.xz
mypcap_20091103152331.pcap.xz
mypcap_20091103152447.pcap.xz
mypcap_20091103152608.pcap.xz
mypcap_20091103152727.pcap.xz
mypcap_20091103152845.pcap.xz
mypcap_20091103153005.pcap.xz
mypcap_20091103153127.pcap.xz
mypcap_20091103153252.pcap.xz
mypcap_20091103153415.pcap.xz
mypcap_20091103153543.pcap.xz
mypcap_20091103153713.pcap.xz
mypcap_20091103153845.pcap.xz
mypcap_20091103154016.pcap.xz
mypcap_20091103154150.pcap.xz
mypcap_20091103154329.pcap.xz
mypcap_20091103154509.pcap.xz
mypcap_20091103154651.pcap.xz
mypcap_20091103154827.pcap.xz
mypcap_20091103155012.pcap.xz
mypcap_20091103155201.pcap.xz
mypcap_20091103155352.pcap.xz
mypcap_20091103155547.pcap.xz
mypcap_20091103155749.pcap.xz
mypcap_20091103155951.pcap.xz
mypcap_20091103160159.pcap.xz
mypcap_20091103160407.pcap.xz
mypcap_20091103160625.pcap.xz
mypcap_20091103160837.pcap.xz
mypcap_20091103161058.pcap.xz
mypcap_20091103161321.pcap.xz
mypcap_20091103161556.pcap.xz
mypcap_20091103161833.pcap.xz
mypcap_20091103162111.pcap.xz
mypcap_20091103162358.pcap.xz
mypcap_20091103162650.pcap.xz
mypcap_20091103162947.pcap.xz
mypcap_20091103163249.pcap.xz
mypcap_20091103163549.pcap.xz
mypcap_20091103163853.pcap.xz
mypcap_20091103164216.pcap.xz
mypcap_20091103164542.pcap.xz
mypcap_20091103164906.pcap.xz
mypcap_20091103165252.pcap.xz
mypcap_20091103165629.pcap.xz
mypcap_20091103170023.pcap.xz
mypcap_20091103170424.pcap.xz
mypcap_20091103170813.pcap.xz
mypcap_20091103171236.pcap.xz
mypcap_20091103171658.pcap.xz
mypcap_20091103172122.pcap.xz
mypcap_20091103172559.pcap.xz
mypcap_20091103173040.pcap.xz
mypcap_20091103173515.pcap.xz
mypcap_20091103174006.pcap.xz
mypcap_20091103174503.pcap.xz
mypcap_20091103174959.pcap.xz
mypcap_20091103175455.pcap.xz
mypcap_20091103180006.pcap.xz
mypcap_20091103180526.pcap.xz
mypcap_20091103181050.pcap.xz
mypcap_20091103181608.pcap.xz
mypcap_20091103182124.pcap.xz
mypcap_20091103182707.pcap.xz
mypcap_20091103183234.pcap.xz
mypcap_20091103183813.pcap.xz
mypcap_20091103184339.pcap.xz
mypcap_20091103184915.pcap.xz
mypcap_20091103185430.pcap.xz
mypcap_20091103190007.pcap.xz
mypcap_20091103190534.pcap.xz
mypcap_20091103191126.pcap.xz
mypcap_20091103191649.pcap.xz
mypcap_20091103192226.pcap.xz
mypcap_20091103192806.pcap.xz
mypcap_20091103193405.pcap.xz
mypcap_20091103193945.pcap.xz
mypcap_20091103194524.pcap.xz
mypcap_20091103195058.pcap.xz
mypcap_20091103195632.pcap.xz
mypcap_20091103200216.pcap.xz
mypcap_20091103200758.pcap.xz
mypcap_20091103201327.pcap.xz
mypcap_20091103201902.pcap.xz
mypcap_20091103202442.pcap.xz
mypcap_20091103203015.pcap.xz
mypcap_20091103203601.pcap.xz
mypcap_20091103204139.pcap.xz
mypcap_20091103204714.pcap.xz
mypcap_20091103205240.pcap.xz
mypcap_20091103205810.pcap.xz
mypcap_20091103210322.pcap.xz
mypcap_20091103210844.pcap.xz
mypcap_20091103211404.pcap.xz
mypcap_20091103211941.pcap.xz
mypcap_20091103212525.pcap.xz
mypcap_20091103213107.pcap.xz
mypcap_20091103213651.pcap.xz
mypcap_20091103214236.pcap.xz
mypcap_20091103214814.pcap.xz
mypcap_20091103215421.pcap.xz
mypcap_20091103220009.pcap.xz
mypcap_20091103220555.pcap.xz
mypcap_20091103221155.pcap.xz
mypcap_20091103221747.pcap.xz
mypcap_20091103222327.pcap.xz
mypcap_20091103222907.pcap.xz
mypcap_20091103223505.pcap.xz
mypcap_20091103224040.pcap.xz
mypcap_20091103224538.pcap.xz
mypcap_20091103225131.pcap.xz
mypcap_20091103225707.pcap.xz
mypcap_20091103230237.pcap.xz
mypcap_20091103230837.pcap.xz
mypcap_20091103231432.pcap.xz
mypcap_20091103232023.pcap.xz
mypcap_20091103232606.pcap.xz
mypcap_20091103233202.pcap.xz
mypcap_20091103233812.pcap.xz
mypcap_20091103234405.pcap.xz
mypcap_20091103234956.pcap.xz
mypcap_20091103235558.pcap.xz
"""

# Convert the string block into a Python list
file_list = [line.strip() for line in raw_filenames.strip().splitlines() if line.strip()]

# Base URL
base_url = "https://share.ant.isi.edu/tracedist/fjWwp5sPaJsOwgb4CIjP/DARPA_Scalable_Network_Monitoring-20091103/set1/"

# Open each file URL in a new tab in Chrome
for file in file_list:
    full_url = base_url + file
    print(f"Opening {full_url}")
    webbrowser.open_new_tab(full_url)
    time.sleep(360)  
