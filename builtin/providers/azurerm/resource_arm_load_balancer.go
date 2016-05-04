package azurerm

import (
	"bytes"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/arm/network"
	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/schema"
	"log"
	"strings"
)

// resourceArmLoadBalancer returns the *schema.Resource
// associated to load balancer resources on ARM.
func resourceArmLoadBalancer() *schema.Resource {
	return &schema.Resource{
		Create: resourceArmLoadBalancerCreate,
		Read:   resourceArmLoadBalancerRead,
		Update: resourceArmLoadBalancerUpdate,
		Delete: resourceArmLoadBalancerDelete,

		Schema: map[string]*schema.Schema{
			"id": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},

			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"type": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			"resource_group_name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},

			"location": &schema.Schema{
				Type:      schema.TypeString,
				Required:  true,
				StateFunc: azureRMNormalizeLocation,
			},
			"tags": tagsSchema(),
			"backend_pool": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
				Set: resourceArmLoadBalancerBackendPoolHash,
			},
			"frontend_ip": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
						"private_ip_address": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},
						"allocation_method": &schema.Schema{
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validateAllocationMethod,
						},
						"subnet": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},
						"public_ip_address": &schema.Schema{
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
				Set: resourceArmLoadBalancerFrontIpHash,
			},
			"probe": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
						"id": &schema.Schema{
							Type:     schema.TypeString,
							Computed: true,
						},
						"protocol": &schema.Schema{
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validateProtocolType,
						},
						"port": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},
						"interval": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},
						"number_of_probes": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},
						"request_path": &schema.Schema{
							Type:     schema.TypeInt,
							Optional: true,
						},
					},
				},
				Set: resourceArmLoadBalancerProbeHash,
			},
			"load_balancing_rule": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
						"protocol": &schema.Schema{
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validateProtocolType,
						},
						"frontend_port": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},
						"backend_port": &schema.Schema{
							Type:     schema.TypeInt,
							Required: true,
						},
						"frontend_ip_name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
						"backend_pool_name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
						"probe_name": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
				Set: resourceArmLoadBalancerRuleHash,
			},
		},
	}
}

func validateAllocationMethod(v interface{}, k string) (ws []string, errors []error) {
	value := strings.ToLower(v.(string))
	allocations := map[string]bool{
		"static":  true,
		"dynamic": true,
	}

	if !allocations[value] {
		errors = append(errors, fmt.Errorf("Allocation method can only be Static of Dynamic"))
	}
	return
}

func validateProtocolType(v interface{}, k string) (ws []string, errors []error) {
	value := strings.ToLower(v.(string))
	allocations := map[string]bool{
		"tcp": true,
		"udp": true,
	}

	if !allocations[value] {
		errors = append(errors, fmt.Errorf("Allocation method can only be Static of Dynamic"))
	}
	return
}

func resourceArmLoadBalancerFrontIpHash(v interface{}) int {
	log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerFrontIpHash[enter]")
	defer log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerFrontIpHash[exit]")

	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["name"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["allocation_method"].(string)))
	if m["subnet"] != nil {
		buf.WriteString(fmt.Sprintf("%s-", m["subnet"].(string)))
	}
	if m["public_ip_address"] != nil {
		buf.WriteString(fmt.Sprintf("%s-", m["public_ip_address"].(string)))
	}
	return hashcode.String(buf.String())
}

func resourceArmLoadBalancerBackendPoolHash(v interface{}) int {
	log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerFrontIpHash[enter]")
	defer log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerFrontIpHash[exit]")

	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["name"].(string)))
	return hashcode.String(buf.String())
}

func resourceArmLoadBalancerRuleHash(v interface{}) int {
	log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerLbRuleHash[enter]")
	defer log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerLbRuleHash[exit]")

	var buf bytes.Buffer
	m := v.(map[string]interface{})

	buf.WriteString(fmt.Sprintf("%s-", m["name"].(string)))
	buf.WriteString(fmt.Sprintf("%d-", m["frontend_port"].(int)))
	buf.WriteString(fmt.Sprintf("%d-", m["backend_port"].(int)))
	buf.WriteString(fmt.Sprintf("%s-", m["protocol"].(string)))
	return hashcode.String(buf.String())
}

func resourceArmLoadBalancerProbeHash(v interface{}) int {
	log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerLbRuleHash[enter]")
	defer log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerLbRuleHash[exit]")

	var buf bytes.Buffer
	m := v.(map[string]interface{})

	buf.WriteString(fmt.Sprintf("%s-", m["name"].(string)))
	buf.WriteString(fmt.Sprintf("%d-", m["port"].(int)))
	buf.WriteString(fmt.Sprintf("%d-", m["interval"].(int)))
	buf.WriteString(fmt.Sprintf("%d-", m["number_of_probes"].(int)))
	buf.WriteString(fmt.Sprintf("%s-", m["protocol"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["request_path"].(string)))
	return hashcode.String(buf.String())
}

func inflateBackendPools(d *schema.ResourceData) (*[]network.BackendAddressPool, error) {
	log.Printf("[resourceArmProbe] inflateProbes[enter]")
	defer log.Printf("[resourceArmProbe] inflateProbes[exit]")

	returnRules := []network.BackendAddressPool{}

	allPools := d.Get("backend_pool").(*schema.Set).List()
	for i := 0; i < len(allPools); i++ {
		poolsMap := allPools[i].(map[string]interface{})
		poolName := poolsMap["name"].(string)
		poolsStruct := network.BackendAddressPool{Name: &poolName}
		returnRules = append(returnRules, poolsStruct)
	}
	return &returnRules, nil
}

func inflateProbes(d *schema.ResourceData) (*[]network.Probe, error) {
	log.Printf("[resourceArmProbe] inflateProbes[enter]")
	defer log.Printf("[resourceArmProbe] inflateProbes[exit]")

	returnRules := []network.Probe{}

	allProbes := d.Get("probe").(*schema.Set).List()
	for i := 0; i < len(allProbes); i++ {
		probesMap := allProbes[i].(map[string]interface{})

		probeName := probesMap["name"].(string)
		protocol := probesMap["protocol"].(string)
		requestPath := probesMap["request_path"].(string)
		port := probesMap["port"].(int)
		interval := probesMap["interval"].(int)
		numberOfProbes := probesMap["number_of_probes"].(int)

		probeProps := network.ProbePropertiesFormat{
			Port:              &port,
			IntervalInSeconds: &interval,
			NumberOfProbes:    &numberOfProbes,
			Protocol:          network.ProbeProtocol(protocol),
		}

		if requestPath != "" && network.ProbeProtocol(protocol) != network.ProbeProtocolHTTP {
			return nil, fmt.Errorf("When using HTTP there must be a request path", probeName)
		}
		if requestPath != "" {
			probeProps.RequestPath = &requestPath
		}

		probeStruct := network.Probe{Name: &probeName, Properties: &probeProps}
		returnRules = append(returnRules, probeStruct)
	}
	return &returnRules, nil
}

func inflateFrontendIps(d *schema.ResourceData) (*[]network.FrontendIPConfiguration, error) {
	log.Printf("[resourceArmLoadBalancer] pullOutFrontEndIps[enter]")
	defer log.Printf("[resourceArmLoadBalancer] pullOutFrontEndIps[exit]")

	returnRules := []network.FrontendIPConfiguration{}

	allFrontedIps := d.Get("frontend_ip").(*schema.Set).List()
	for i := 0; i < len(allFrontedIps); i++ {
		frontedIp := allFrontedIps[i].(map[string]interface{})

		frontedIpName := frontedIp["name"].(string)
		frontedIpAllocationMethod := network.IPAllocationMethod(frontedIp["allocation_method"].(string))
		frontedIpSubnet := frontedIp["subnet"].(string)
		frontedIpPublicIpAddress := frontedIp["public_ip_address"].(string)
		frontedIpPrivateIpAddress := frontedIp["private_ip_address"].(string)

		if frontedIpSubnet == "" && frontedIpPublicIpAddress == "" {
			var logMsg = fmt.Sprintf("[ERROR] Either a subnet of a public ip address must be provided")
			log.Printf("[resourceArmLoadBalancer] %s", logMsg)
			return nil, fmt.Errorf(logMsg)
		}

		if frontedIpPrivateIpAddress == "" && frontedIpAllocationMethod == network.Static {
			var logMsg = fmt.Sprintf("An private IP address must be provided if static allocation is used.")
			log.Printf("[resourceArmLoadBalancer] %s", logMsg)
			return nil, fmt.Errorf(logMsg)
		}

		ipProps := network.FrontendIPConfigurationPropertiesFormat{
			PrivateIPAllocationMethod: frontedIpAllocationMethod}

		if frontedIpSubnet != "" {
			subnet := network.Subnet{ID: &frontedIpSubnet}
			ipProps.Subnet = &subnet
		}
		if frontedIpPublicIpAddress != "" {
			pubIp := network.PublicIPAddress{ID: &frontedIpPublicIpAddress}
			ipProps.PublicIPAddress = &pubIp
		}
		if frontedIpPrivateIpAddress != "" {
			ipProps.PrivateIPAddress = &frontedIpPrivateIpAddress
		}

		frontendIpConf := network.FrontendIPConfiguration{Name: &frontedIpName, Properties: &ipProps}
		returnRules = append(returnRules, frontendIpConf)
	}
	return &returnRules, nil
}

func inflateLbRules(d *schema.ResourceData, loadBalancer *network.LoadBalancer) (*[]network.LoadBalancingRule, error) {
	log.Printf("[resourceArmLoadBalancer] pullOutLbRules[enter]")
	defer log.Printf("[resourceArmLoadBalancer] pullOutLbRules[exit]")

	backendPools := loadBalancer.Properties.BackendAddressPools
	frontendIps := loadBalancer.Properties.FrontendIPConfigurations
	probes := loadBalancer.Properties.Probes

	returnRules := []network.LoadBalancingRule{}
	x := d.Get("load_balancing_rule")
	allRules := x.(*schema.Set).List()

	for i := 0; i < len(allRules); i++ {
		rule := allRules[i].(map[string]interface{})

		ruleName := rule["name"].(string)
		ruleProtocol := network.TransportProtocol(rule["protocol"].(string))
		ruleFrontendPort := rule["frontend_port"].(int)
		ruleBackendPort := rule["backend_port"].(int)

		frontendId, err := findFrontendIdByName(frontendIps, rule["frontend_ip_name"].(string))
		if err != nil {
			return nil, err
		}
		probeId, err := findProbeIdByName(probes, rule["probe_name"].(string))
		if err != nil {
			return nil, err
		}
		backendId, err := findBackendPoolIdByName(backendPools, rule["backend_pool_name"].(string))
		if err != nil {
			return nil, err
		}

		frontRef := network.SubResource{ID: frontendId}
		probeRef := network.SubResource{ID: probeId}
		backRef := network.SubResource{ID: backendId}

		rulesProps := network.LoadBalancingRulePropertiesFormat{
			FrontendIPConfiguration: &frontRef,
			BackendAddressPool:      &backRef,
			Probe:                   &probeRef,
			BackendPort:             &ruleBackendPort,
			FrontendPort:            &ruleFrontendPort,
			Protocol:                ruleProtocol,
		}

		ruleType := network.LoadBalancingRule{
			Name:       &ruleName,
			Properties: &rulesProps,
		}

		returnRules = append(returnRules, ruleType)
	}
	return &returnRules, nil
}

func resourceArmLoadBalancerCreate(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerCreate[enter]")
	defer log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerCreate[exit]")

	lbClient := meta.(*ArmClient).loadBalancerClient

	// first; fetch a bunch of fields:
	typ := d.Get("type").(string)
	name := d.Get("name").(string)
	location := d.Get("location").(string)
	resGrp := d.Get("resource_group_name").(string)

	loadBalancer := network.LoadBalancer{
		Name:       &name,
		Type:       &typ,
		Location:   &location,
		Properties: &network.LoadBalancerPropertiesFormat{},
	}

	fipconfs, err := inflateFrontendIps(d)
	if err != nil {
		return err
	}
	loadBalancer.Properties.FrontendIPConfigurations = fipconfs

	probes, err := inflateProbes(d)
	if err != nil {
		return err
	}
	loadBalancer.Properties.Probes = probes

	pools, err := inflateBackendPools(d)
	if err != nil {
		return err
	}
	loadBalancer.Properties.BackendAddressPools = pools

	resp, err := lbClient.CreateOrUpdate(resGrp, name, loadBalancer)
	if err != nil {
		log.Printf("[resourceArmLoadBalancer] ERROR LB got status %s", err.Error())
		return fmt.Errorf("Error issuing Azure ARM creation request for load balancer '%s': %s", name, err)
	}
	log.Printf("[resourceArmLoadBalancer] Create LB got status %d", resp.StatusCode)
	d.SetId(*resp.ID)
	// XXXX Now we have the IDs that match the frontend, probe, and backend names so we can setup the rules
	log.Printf("[resourceArmLoadBalancer] We have the IDs now updating to set rules")
	loadBalancer.Properties.LoadBalancingRules, err = inflateLbRules(d, &resp)
	if err != nil {
		return err
	}
	resp, err = lbClient.CreateOrUpdate(resGrp, name, loadBalancer)
	if err != nil {
		log.Printf("[resourceArmLoadBalancer] ERROR LB got status %s", err.Error())
		return fmt.Errorf("Error issuing Azure ARM creation request for load balancer '%s': %s", name, err)
	}
	return iResourceArmLoadBalancerRead(d, meta)
}

func resourceArmLoadBalancerUpdate(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerUpdate[enter]")
	defer log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerUpdate[exit]")

	return resourceArmLoadBalancerCreate(d, meta)
}

func resourceArmLoadBalancerDelete(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerDelete[enter]")
	defer log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerDelete[exit]")

	lbClient := meta.(*ArmClient).loadBalancerClient

	name := d.Get("name").(string)
	resGroup := d.Get("resource_group_name").(string)

	log.Printf("Issuing deletion request to Azure ARM for load balancer '%s'.", name)

	resp, err := lbClient.Delete(resGroup, name)
	if err != nil {
		return fmt.Errorf("Error issuing Azure ARM delete request for load balancer '%s': %s", name, err)
	}

	log.Printf("[resourceArmLoadBalancer] delete response %d %s", resp.StatusCode, resp.Status)

	return nil
}

// resourceArmLoadBalancerRead goes ahead and reads the state of the corresponding ARM load balancer.
func iResourceArmLoadBalancerRead(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[resourceArmLoadBalancer] iResourceArmLoadBalancerRead[enter]")
	defer log.Printf("[resourceArmLoadBalancer] iResourceArmLoadBalancerRead[exit]")

	lbClient := meta.(*ArmClient).loadBalancerClient

	name := d.Get("name").(string)
	resGrp := d.Get("resource_group_name").(string)

	log.Printf("[INFO] Issuing read request of load balancer '%s' off Azure.", name)

	loadBalancer, err := lbClient.Get(resGrp, name, "")
	if err != nil {
		return fmt.Errorf("Error reading the state of the load balancer off Azure: %s", err)
	}

	probesSet := flattenProbes(loadBalancer.Properties.Probes)
	d.Set("probe", probesSet)

	frontendsSet := flattenFrontendIps(loadBalancer.Properties.FrontendIPConfigurations)
	d.Set("frontend_ip", frontendsSet)

	poolsSet := flattenBackendPools(loadBalancer.Properties.BackendAddressPools)
	d.Set("backend_pool", poolsSet)

	rulesSet, err := flattenBackendRules(&loadBalancer)
	if err != nil {
		return err
	}
	d.Set("load_balancing_rule", rulesSet)

	d.SetId(*loadBalancer.ID)
	d.Set("name", *loadBalancer.Name)
	d.Set("type", *loadBalancer.Type)
	d.Set("location", *loadBalancer.Location)
	if loadBalancer.Tags != nil {
		flattenAndSetTags(d, loadBalancer.Tags)
	}

	return nil
}

// resourceArmLoadBalancerRead goes ahead and reads the state of the corresponding ARM load balancer.
func resourceArmLoadBalancerRead(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerRead[enter]")
	defer log.Printf("[resourceArmLoadBalancer] resourceArmLoadBalancerRead[exit]")

	return iResourceArmLoadBalancerRead(d, meta)
}

func findProbeIdByName(probeArray *[]network.Probe, probeName string) (*string, error) {
	// Find the correct LB
	for i := 0; i < len(*probeArray); i++ {
		tmpProbe := (*probeArray)[i]
		if *tmpProbe.Name == probeName {
			return tmpProbe.ID, nil
		}
	}
	return nil, fmt.Errorf("Error loading the probe named %s", probeName)
}

func findFrontendIdByName(frontendIpConfs *[]network.FrontendIPConfiguration, frontendName string) (*string, error) {
	// Find the correct LB
	for i := 0; i < len(*frontendIpConfs); i++ {
		tmpFrontendIp := (*frontendIpConfs)[i]
		if *tmpFrontendIp.Name == frontendName {
			return tmpFrontendIp.ID, nil
		}
	}
	return nil, fmt.Errorf("Error loading the frontend IP named %s", frontendName)
}

func findBackendPoolIdByName(backendPoolArray *[]network.BackendAddressPool, backendPoolName string) (*string, error) {
	// Find the correct LB
	for i := 0; i < len(*backendPoolArray); i++ {
		tmpRule := (*backendPoolArray)[i]
		if *tmpRule.Name == backendPoolName {
			return tmpRule.ID, nil
		}
	}
	return nil, fmt.Errorf("Error loading the rule named %s", backendPoolArray)
}

func findProbeNameById(probeArray *[]network.Probe, probeId string) (*string, error) {
	// Find the correct LB
	for i := 0; i < len(*probeArray); i++ {
		tmpProbe := (*probeArray)[i]
		if *tmpProbe.ID == probeId {
			return tmpProbe.Name, nil
		}
	}
	return nil, fmt.Errorf("Error loading the probe named %s", probeId)
}

func findFrontendNameById(frontendIpConfs *[]network.FrontendIPConfiguration, frontendId string) (*string, error) {
	// Find the correct LB
	for i := 0; i < len(*frontendIpConfs); i++ {
		tmpFrontendIp := (*frontendIpConfs)[i]
		if *tmpFrontendIp.ID == frontendId {
			return tmpFrontendIp.Name, nil
		}
	}
	return nil, fmt.Errorf("Error loading the frontend IP named %s", frontendId)
}

func findBackendPoolNameById(backendPoolArray *[]network.BackendAddressPool, backendPoolId string) (*string, error) {
	// Find the correct LB
	for i := 0; i < len(*backendPoolArray); i++ {
		tmpRule := (*backendPoolArray)[i]
		if *tmpRule.ID == backendPoolId {
			return tmpRule.Name, nil
		}
	}
	return nil, fmt.Errorf("Error loading the rule named %s", backendPoolArray)
}

func flattenFrontendIps(frontendIps *[]network.FrontendIPConfiguration) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(*frontendIps))
	for _, fIp := range *frontendIps {
		f := make(map[string]interface{})

		f["id"] = *fIp.ID
		f["name"] = *fIp.Name
		if fIp.Properties != nil {
			props := fIp.Properties

			if props.PrivateIPAddress != nil {
				f["private_ip_address"] = *props.PrivateIPAddress
			}
			f["allocation_method"] = string(props.PrivateIPAllocationMethod)
			if props.Subnet != nil {
				f["subnet"] = *props.Subnet.ID
			}
			if props.PublicIPAddress != nil {
				f["public_ip_address"] = *props.PublicIPAddress.ID
			}
		}
		result = append(result, f)
	}
	return result
}

func flattenProbes(probes *[]network.Probe) *schema.Set {
	probeSet := schema.Set{F: resourceArmLoadBalancerProbeHash}

	for _, probe := range *probes {
		p := make(map[string]interface{})

		p["id"] = *probe.ID
		p["name"] = *probe.Name
		if probe.Properties != nil {
			props := probe.Properties

			if props.Port != nil {
				p["port"] = *props.Port
			}
			p["protocol"] = string(props.Protocol)
			if props.IntervalInSeconds != nil {
				p["interval"] = *props.IntervalInSeconds
			}
			if props.NumberOfProbes != nil {
				p["number_of_probes"] = *props.NumberOfProbes
			}
			if props.RequestPath != nil {
				p["request_path"] = *props.RequestPath
			}
		}
		probeSet.Add(p)
	}
	return &probeSet
}

func flattenBackendPools(pools *[]network.BackendAddressPool) *schema.Set {
	backendSet := schema.Set{F: resourceArmLoadBalancerBackendPoolHash}

	for _, pool := range *pools {
		p := make(map[string]interface{})
		p["id"] = *pool.ID
		p["name"] = *pool.Name
		backendSet.Add(p)
	}
	return &backendSet
}

func flattenBackendRules(lb *network.LoadBalancer) (*schema.Set, error) {
	rules := lb.Properties.LoadBalancingRules

	ruleSet := schema.Set{F: resourceArmLoadBalancerRuleHash}

	for _, rule := range *rules {
		p := make(map[string]interface{})

		p["id"] = *rule.ID
		p["name"] = *rule.Name
		if rule.Properties != nil {
			props := rule.Properties

			p["protocol"] = string(props.Protocol)
			p["frontend_port"] = *props.FrontendPort
			p["backend_port"] = *props.BackendPort

			if props.BackendAddressPool != nil {
				poolName, err := findBackendPoolNameById(lb.Properties.BackendAddressPools, *props.BackendAddressPool.ID)
				if err != nil {
					return nil, err
				}
				p["backend_pool_name"] = *poolName

				frontendName, err := findFrontendNameById(lb.Properties.FrontendIPConfigurations, *props.FrontendIPConfiguration.ID)
				if err != nil {
					return nil, err
				}
				p["frontend_ip_name"] = *frontendName

				probeName, err := findProbeNameById(lb.Properties.Probes, *props.Probe.ID)
				if err != nil {
					return nil, err
				}
				p["probe_name"] = *probeName
			}
		}
		ruleSet.Add(p)
	}
	return &ruleSet, nil
}
