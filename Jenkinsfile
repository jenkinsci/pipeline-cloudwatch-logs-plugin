if (infra.isRunningOnJenkinsInfra()) {
    // ci.jenkins.io
    buildPlugin(platforms: ['linux'])
} else if (env.CHANGE_FORK == null) { // TODO pending JENKINS-45970
    // to run tests on AWS
    buildPluginOnAWS()
} else {
    error 'Run tests manually.'
}
