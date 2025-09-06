enum ParameterCategory {
    # Parameter will be satisfied by output from a previous function in the workflow
    SatisfiedByDependency
    
    # Parameter is available in the initial workflow context
    AvailableInContext
    
    # Parameter is missing from both workflow dependencies and initial context
    MissingFromContext
}