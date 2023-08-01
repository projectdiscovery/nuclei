log("Regions: "+template["regions"]) // just like console.log . currently does not support formatting

template["regions"].forEach(element => {
    set("region", element) // set variable in template context
    http("extract-vpcs")

    poll() // updates 'template' variable with latest data

    log("Got VPCs: "+template["vpcs"]+" from region: "+element)

    template["vpcs"].forEach(element => {
        set("vpcId", element) // set variable in template context
        http("extract-flow-logs")
    });
});
// log("Got VPCs: "+template["vpcs"]+" from all regions") 
// template["vpcs"].forEach(element => {
//     set("vpcId", element) // set variable in template context
//     http("extract-flow-logs")
// });