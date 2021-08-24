import scipy.stats 

data = [[(148, 13024.96),(236, 19034.88),(19, 1817.0),(202, 16665.88),(2, 414.12),(41, 3643.0),(67, 5801.0),(231, 19024.74),(219, 18785.34),(214, 16921.88),(207, 18117.84),(187, 15761.0),(136, 11528.0),(0, 240.0),(85, 7295.0),(6, 723.24),(223, 19498.96),(9, 927.78),(238, 19994.0),(177, 14931.0),(130, 11250.6),(69, 5967.0)]
,[(159, 10955.82),(16, 1136.8),(152, 10272.0),(121, 7867.2),(190, 13587.08),(155, 10473.0),(128, 9183.84),(191, 12627.3),(149, 10272.42),(215, 14493.0),(89, 6293.04),(101, 6855.0),(233, 15699.0),(228, 15364.0),(32, 2232.0),(33, 2299.0),(1, 155.0),(81, 5294.4),(247, 16969.74),(230, 15188.04),(120, 8128.0),(243, 15714.24)]
,[(173, 14617.0),(237, 19593.14),(37, 3256.86),(55, 4705.0),(0, 88.4),(49, 3948.94),(21, 1922.96),(6, 589.0),(228, 19237.0),(27, 2353.0),(249, 21841.04),(245, 20251.7),(140, 12081.9),(149, 12096.96),(53, 4809.22),(114, 9661.0),(16, 1429.0),(141, 11690.42),(201, 16969.0),(238, 20077.0),(248, 20917.0),(138, 11443.46)]
,[(16, 1232.4),(82, 5805.0),(172, 12105.0),(150, 10565.0),(180, 12918.3),(241, 16257.6),(130, 9165.0),(74, 4930.3),(20, 1494.3),(255, 17915.0),(197, 14132.1),(198, 13368.0),(71, 5035.0),(101, 7135.0),(251, 17635.0),(220, 15465.0),(174, 12979.7),(113, 7815.5),(64, 4635.9),(114, 8045.0),(80, 5778.3),(47, 3220.8)]
,[(110, 13802.64),(5, 617.0),(250, 31982.08),(147, 18083.0),(9, 1175.54),(24, 2835.84),(159, 19559.0),(181, 21819.7),(243, 30488.82),(53, 6521.0),(72, 8858.0),(112, 13502.44),(71, 8735.0),(23, 2831.0),(191, 24434.8),(254, 29994.24),(44, 5738.84),(209, 25194.82),(3, 371.0),(199, 24479.0),(99, 12179.0),(146, 17600.8)]
,[(9, 926.0),(202, 16366.0),(104, 8526.0),(143, 11180.16),(180, 14606.0),(164, 13059.48),(138, 11695.84),(51, 4286.0),(205, 16938.12),(123, 9845.08),(22, 2005.32),(33, 2675.24),(223, 18767.84),(179, 14526.0),(194, 15726.0),(200, 15557.76),(72, 5966.0),(24, 2126.0),(189, 15326.0),(217, 16512.04),(12, 1189.32),(112, 8982.68)]
,[(151, 17331.0),(145, 15648.18),(7, 951.6),(183, 20979.0),(192, 22885.2),(130, 14339.52),(120, 13797.0),(220, 24693.06),(208, 24782.16),(146, 16425.78),(207, 24189.3),(83, 9579.0),(11, 1371.0),(255, 28603.26),(189, 21663.0),(14, 1713.0),(241, 27591.0),(39, 4289.22),(166, 19041.0),(195, 21900.06),(35, 4189.14),(173, 19839.0)]
,[(141, 7182.24),(221, 10746.0),(254, 12576.6),(145, 7098.0),(162, 8072.28),(54, 2566.2),(107, 5379.48),(147, 7050.12),(7, 492.96),(252, 11744.64),(180, 8953.56),(168, 8202.0),(95, 4698.0),(146, 6717.24),(27, 1434.0),(199, 9690.0),(1, 186.0),(144, 7050.0),(72, 3594.0),(5, 362.88),(220, 10698.0),(108, 5215.56)]
,[(27, 3148.08),(39, 4092.48),(116, 12925.64),(149, 15593.0),(188, 20394.4),(155, 16211.0),(122, 13068.24),(245, 24971.38),(251, 26099.0),(68, 7105.0),(193, 20125.0),(249, 25375.14),(183, 19095.0),(50, 5396.0),(83, 8795.0),(174, 17804.64),(173, 18426.3),(220, 22906.0),(199, 21572.72),(114, 11988.0),(52, 5602.0),(145, 14270.14)]
,[(158, 19279.28),(77, 8954.0),(165, 18986.0),(160, 18047.68),(124, 14884.48),(208, 23888.0),(60, 7016.0),(164, 18117.12),(201, 23090.0),(91, 10550.0),(106, 12505.2),(141, 16250.0),(223, 26109.96),(219, 24136.32),(18, 2228.0),(103, 11918.0),(225, 26342.52),(122, 13238.96),(140, 16781.44),(65, 7586.0),(200, 23435.52),(13, 1624.84)]
,[(34, 3532.0),(83, 7972.14),(49, 5248.88),(127, 12666.5),(180, 18278.0),(225, 22823.0),(162, 16460.0),(229, 23227.0),(212, 21940.2),(223, 21716.16),(232, 24000.6),(178, 17714.48),(90, 9188.0),(32, 3330.0),(143, 15413.46),(255, 25335.94),(163, 16892.22),(110, 11208.0),(1, 199.0),(211, 21409.0),(128, 13547.04),(117, 11438.4)]
,[(161, 8678.0),(244, 13077.0),(13, 834.0),(91, 4868.64),(153, 8419.08),(80, 4121.9),(216, 12056.72),(178, 9387.42),(49, 2742.0),(237, 11943.64),(142, 7671.0),(68, 3749.0),(234, 12547.0),(163, 8432.64),(23, 1391.28),(133, 7194.0),(179, 10017.28),(121, 6558.0),(115, 6240.0),(93, 4972.52),(139, 7662.24),(184, 9501.12)]
,[(236, 12636.0),(98, 5109.12),(135, 7574.32),(9, 605.0),(249, 13591.5),(82, 4205.56),(24, 1456.0),(52, 2884.0),(101, 5481.0),(159, 8383.9),(129, 6965.0),(235, 12583.0),(210, 11258.0),(222, 11894.0),(106, 5860.92),(42, 2354.0),(102, 5644.68),(65, 3573.0),(191, 10866.06),(7, 489.02),(178, 9753.24),(186, 9586.56)]
,[(172, 16709.64),(56, 5147.52),(128, 12202.0),(136, 12184.28),(133, 13184.08),(222, 21132.0),(205, 19907.34),(29, 2797.0),(53, 5077.0),(140, 13342.0),(80, 7794.84),(188, 17902.0),(168, 16002.0),(167, 15270.72),(39, 3971.82),(131, 11987.52),(7, 707.0),(134, 12516.56),(162, 15432.0),(92, 8606.36),(91, 8687.0),(198, 18474.96)]
,[(250, 19107.92),(64, 4795.0),(103, 7642.0),(132, 9759.0),(252, 18519.0),(78, 5817.0),(15, 1218.0),(80, 5843.74),(52, 4075.76),(212, 14663.06),(155, 11666.76),(234, 16516.8),(95, 7058.0),(152, 10994.62),(117, 8837.28),(101, 7046.24),(184, 13826.1),(177, 12783.12),(7, 634.0),(151, 11146.0),(156, 11971.44),(62, 4649.0)]
,[(128, 14229.0),(94, 9859.66),(87, 10107.76),(251, 26648.64),(52, 5986.38),(216, 23430.82),(221, 25437.36),(63, 7079.0),(222, 24569.0),(137, 14610.24),(115, 13054.98),(66, 7260.82),(134, 15186.78),(224, 24789.0),(203, 22479.0),(245, 27099.0),(39, 4439.0),(93, 10379.0),(225, 24899.0),(149, 16208.22),(205, 24060.94),(69, 7739.0)]
,[(206, 19714.0),(183, 17529.0),(31, 3089.0),(115, 10847.62),(140, 13444.0),(252, 22638.96),(203, 20206.16),(129, 11655.06),(181, 17339.0),(174, 16340.52),(170, 16945.76),(186, 17457.72),(187, 17909.0),(40, 3865.12),(37, 3659.0),(255, 24369.0),(232, 23071.36),(35, 3469.0),(192, 19119.36),(141, 13268.22),(0, 146.88),(60, 5844.0)]
,[(200, 16475.0),(177, 14589.0),(191, 16366.48),(31, 2617.0),(125, 10531.5),(17, 1469.0),(56, 4667.0),(6, 544.32),(87, 7353.18),(157, 12172.06),(33, 2836.62),(176, 14507.0),(106, 9293.02),(242, 19919.0),(4, 403.0),(26, 2207.0),(169, 13933.0),(46, 3770.06),(127, 10908.56),(23, 1882.56),(126, 10615.14),(95, 7707.7)]
,[(196, 10456.02),(149, 7854.0),(32, 1924.74),(146, 7392.96),(144, 7599.0),(57, 2972.28),(227, 11832.0),(153, 8058.0),(61, 3567.96),(126, 6681.0),(71, 4031.04),(2, 349.86),(115, 6120.0),(28, 1683.0),(86, 4733.82),(169, 8696.52),(222, 11577.0),(33, 1899.24),(44, 2598.96),(241, 12546.0),(74, 4190.16),(159, 8364.0)]
,[(32, 3539.12),(230, 23797.0),(219, 23570.56),(229, 23220.12),(216, 22802.1),(218, 22109.78),(80, 8680.88),(251, 25960.0),(128, 13291.0),(121, 12318.6),(133, 13806.0),(253, 26166.0),(122, 12673.0),(136, 13832.7),(105, 10922.0),(31, 3300.0),(70, 7463.34),(144, 14341.44),(182, 18853.0),(123, 12009.44),(111, 11540.0),(16, 1649.7)]
,[(235, 27034.0),(125, 14494.0),(204, 23500.0),(182, 19732.48),(197, 22702.0),(151, 17108.84),(107, 12442.0),(4, 686.0),(220, 25830.48),(131, 14570.88),(173, 19966.0),(61, 7198.0),(56, 6628.0),(216, 23873.28),(176, 21526.48),(109, 12670.0),(67, 8039.64),(251, 28280.84),(211, 25269.92),(72, 8282.96),(156, 18749.12),(101, 11758.0)]
,[(247, 12712.0),(233, 11518.08),(218, 11233.0),(55, 2920.0),(185, 9550.0),(189, 9754.0),(255, 13382.4),(222, 10979.52),(231, 12133.92),(204, 10519.0),(212, 11582.62),(176, 9091.0),(68, 3583.0),(53, 2818.0),(243, 12758.16),(246, 12407.78),(155, 8340.8),(112, 5593.92),(135, 7000.0),(73, 3607.72),(121, 6411.72),(173, 8759.24)]
,[(98, 11699.4),(101, 11815.0),(25, 3136.5),(135, 15725.0),(75, 8825.0),(3, 512.3),(96, 11464.8),(74, 8710.0),(30, 3650.0),(243, 28145.0),(73, 8938.8),(32, 3724.8),(204, 24606.4),(251, 28483.7),(122, 14230.0),(145, 16875.0),(174, 20614.2),(200, 22736.0),(111, 13483.6),(53, 6295.0),(255, 29525.0),(47, 5268.7)]
,[(7, 1063.18),(118, 13768.0),(249, 28833.0),(163, 18185.28),(254, 29996.16),(116, 13267.24),(154, 17908.0),(17, 2066.88),(89, 10850.32),(21, 2560.74),(86, 10491.52),(238, 27568.0),(62, 7767.68),(156, 17775.24),(95, 11123.0),(75, 8646.54),(229, 26533.0),(113, 13193.0),(80, 9398.0),(146, 16648.24),(226, 26188.0),(153, 17793.0)]
,[(39, 5104.0),(124, 15729.0),(80, 10229.0),(122, 14550.26),(168, 21229.0),(159, 20104.0),(52, 6729.0),(16, 2095.26),(7, 1148.16),(99, 12604.0),(43, 5828.16),(35, 4511.92),(115, 14604.0),(236, 29134.42),(51, 6736.08),(176, 22229.0),(255, 32104.0),(6, 939.84),(200, 25733.58),(138, 17129.42),(143, 18828.16),(146, 18109.42)]
]

flag = ''

for i in range(len(data)):
    xs = []
    ys = []
    for u, v in data[i]:
        xs.append(u)
        ys.append(v)
    res = scipy.stats.linregress(xs, ys)
    flag += chr(int(res.slope + 0.5))

print(flag)