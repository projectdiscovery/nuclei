log(template)

template["regions"].forEach(element => {
    http("extract-vpcs")
});

log("got vpcs")
log(template["vpcs"])