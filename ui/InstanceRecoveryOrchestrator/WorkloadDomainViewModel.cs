namespace InstanceRecoveryOrchestrator
{
    public sealed class WorkloadDomainViewModel
    {
        public WorkloadDomainViewModel(string domainName, string domainType)
        {
            DomainName = domainName;
            DomainType = domainType;
        }

        public string DomainName { get; }
        public string DomainType { get; }
        public string Display => $"{DomainName} ({DomainType})";
    }
}
