template["regions"].forEach(region => {
    set("region",region);
    http("extract-vpcs");
    poll();
    template["vpcs"].forEach(vpcId => {
        set("vpcId",vpcId);
        http("extract-flow-logs");
    })
});