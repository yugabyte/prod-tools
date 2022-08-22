# prod-tools

Tools for production maintenance of YugabyteDB clusters

This will be a collection of tools that can be added as needed when a need arises to solve production issues on YugabyteDB clusters. 
Not all production clusters are running the latest version of YugabyteDB, so the tools we add here need to deal with that.
The advantage of using a separate repository for tools is that these tools can be updated as often as needed without affecting production YugabyteDB deployments.
Also dependencies between these tools should be kept to a minimum, so that they could ideally be downloaded as invdividual scripts.
The preferred language for implementing these tools is Python, and we should keep them compatible with both Python 2.7 and Python 3.x

