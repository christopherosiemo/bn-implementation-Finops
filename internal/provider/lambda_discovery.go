package provider

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func lambdaConfig(s lambdacost.Scope, d model.Document) (model.Document, error) {
	arn := model.String(d, "FunctionArn")
	base, q, e := lambdacost.FunctionARN(s, arn)
	if e != nil {
		return nil, e
	}
	v := model.String(d, "Version")
	if v == "" {
		v = q
	}
	if v == "" {
		return nil, lambdacost.ErrEvidence
	}
	if q != "" && q != v {
		return nil, lambdacost.ErrEvidence
	}
	qualified := base + ":" + v
	arch := model.Strings(d, "Architectures")
	var architecture any
	if len(arch) == 1 {
		architecture = arch[0]
	}
	out := model.Document{"base_function_arn": base, "qualified_arn": qualified, "version": v, "qualifier": v, "model": lambdacost.Model(d), "name": d["FunctionName"], "runtime": d["Runtime"], "handler": d["Handler"], "package_type": d["PackageType"], "code_sha256": d["CodeSha256"], "code_size_bytes": d["CodeSize"], "architecture": architecture, "memory_size_mb": d["MemorySize"], "timeout_seconds": d["Timeout"], "ephemeral_storage_mb": lambdacost.Document(d["EphemeralStorage"])["Size"], "state": d["State"], "state_reason_code": d["StateReasonCode"], "last_update_status": d["LastUpdateStatus"], "last_update_status_reason_code": d["LastUpdateStatusReasonCode"], "last_modified": d["LastModified"], "config_revision_id": d["RevisionId"], "native_config_sha256": d["ConfigSha256"], "vpc": d["VpcConfig"], "execution_role_metadata": d["Role"], "environment_metadata": d["Environment"], "layers": d["Layers"], "tracing": d["TracingConfig"], "dead_letter": d["DeadLetterConfig"], "logging": d["LoggingConfig"], "snap_start": d["SnapStart"], "runtime_version": d["RuntimeVersionConfig"], "file_systems": d["FileSystemConfigs"], "capacity_provider": d["CapacityProviderConfig"], "durable_configuration": d["DurableConfig"], "tenancy_configuration": d["TenancyConfig"], "image_configuration": nil, "native_response_sanitized": true, "unknown_is_zero": false}
	presence := model.Document{}
	for _, key := range []string{"FunctionArn", "Version", "CodeSha256", "Runtime", "Handler", "PackageType", "Architectures", "Timeout", "EphemeralStorage", "VpcConfig", "Layers", "FileSystemConfigs", "Environment", "RuntimeVersionConfig", "Role", "TracingConfig", "DeadLetterConfig", "LoggingConfig", "SnapStart"} {
		_, observed := d[key]
		presence[key] = observed
	}
	out["native_field_presence"] = presence
	out["configuration_epoch_hash"] = lambdacost.Hash(out)
	return out, nil
}

// LambdaDiscover returns one bounded native function page. NextMarker is a
// durable account checkpoint; completion means only the selected API scope.
// Optional denied metadata never erases a discovered function.
func (a *AWS) LambdaDiscover(ctx context.Context, s lambdacost.Scope, sel lambdacost.DiscoverySelection) (lambdacost.Discovery, error) {
	out := lambdacost.Discovery{Functions: []model.Document{}, Coverage: []model.Document{}}
	r, e := newLambdaRead(a, s)
	if e != nil {
		return out, e
	}
	count := sel.MaxFunctions
	if count == 0 {
		count = 10
	}
	if count < 1 || count > 50 || len(sel.Marker) > 4096 {
		return out, lambdacost.ErrEvidence
	}
	if sel.FunctionARN != "" {
		base, qualifier, err := lambdacost.FunctionARN(s, sel.FunctionARN)
		if err != nil || base != sel.FunctionARN || qualifier != "" {
			return out, lambdacost.ErrEvidence
		}
	}
	q := url.Values{"MaxItems": {strconv.Itoa(count)}}
	if sel.Marker != "" {
		q.Set("Marker", sel.Marker)
	}
	page, e := r.get(ctx, "ListFunctions", "/2015-03-31/functions/", q)
	if e != nil {
		return out, e
	}
	if page["Functions"] == nil {
		return out, lambdacost.ErrEvidence
	}
	functions := lambdacost.Rows(page["Functions"])
	if len(functions) > count {
		return out, lambdacost.ErrEvidence
	}
	accountSettings, accountErr := r.get(ctx, "GetAccountSettings", "/2016-08-19/account-settings/", url.Values{})
	seen := map[string]bool{}
	for _, f := range functions {
		base, qual, e := lambdacost.FunctionARN(s, model.String(f, "FunctionArn"))
		if e != nil || qual != "" && qual != "$LATEST" || seen[base] {
			return out, lambdacost.ErrEvidence
		}
		seen[base] = true
		if sel.FunctionARN != "" && base != sel.FunctionARN {
			continue
		}
		name := strings.TrimPrefix(base, "arn:aws:lambda:"+s.Region+":"+s.AccountID+":function:")
		path := "/2015-03-31/functions/" + url.PathEscape(base)
		latest, e := r.get(ctx, "GetFunctionConfiguration", path+"/configuration", url.Values{})
		latestFullConfigurationObserved := e == nil
		coverage := []model.Document{}
		if e != nil {
			latest = f
			coverage = append(coverage, model.Document{"source": "GetFunctionConfiguration", "status": "UNAVAILABLE", "missing_is_zero": false})
		}
		configuration, e := lambdaConfig(s, latest)
		if e != nil {
			return out, e
		}
		configuration["native_configuration_response_observed"] = latestFullConfigurationObserved
		versions := []model.Document{lambdacost.Document(configuration)}
		nativeVersions, e := r.list(ctx, "ListVersionsByFunction", path+"/versions", "Versions", url.Values{"MaxItems": {"50"}})
		if e != nil {
			coverage = append(coverage, model.Document{"source": "ListVersionsByFunction", "status": "UNAVAILABLE", "missing_is_zero": false})
		} else {
			versions = []model.Document{}
			versionSeen := map[string]bool{}
			for _, v := range nativeVersions {
				fullConfigurationObserved := latestFullConfigurationObserved
				vbase, vq, e := lambdacost.FunctionARN(s, model.String(v, "FunctionArn"))
				version := model.String(v, "Version")
				if e != nil || vbase != base || vq != "" && vq != version || versionSeen[version] {
					return out, lambdacost.ErrEvidence
				}
				versionSeen[version] = true
				if version != "$LATEST" {
					full, err := r.get(ctx, "GetFunctionConfiguration", path+"/configuration", url.Values{"Qualifier": {version}})
					fullConfigurationObserved = err == nil
					if err == nil {
						v = full
					} else {
						coverage = append(coverage, model.Document{"source": "GetFunctionConfiguration", "qualifier": version, "status": "UNAVAILABLE"})
					}
				} else {
					v = latest
				}
				c, err := lambdaConfig(s, v)
				if err != nil {
					return out, err
				}
				c["native_configuration_response_observed"] = fullConfigurationObserved
				versions = append(versions, c)
			}
			if !versionSeen["$LATEST"] {
				versions = append(versions, configuration)
			}
		}
		sort.Slice(versions, func(i, j int) bool {
			return model.String(versions[i], "version") < model.String(versions[j], "version")
		})
		configuration["versions"] = versions
		configuration["name"] = name
		configuration["account_id"] = s.AccountID
		configuration["region"] = s.Region
		configuration["coverage"] = coverage
		configuration["inventory_model_coverage"] = model.Document{"event_functions": "OBSERVED", "web_functions": "NOT_COLLECTED_SEPARATE_API", "microvms": "NOT_COLLECTED_SEPARATE_API", "complete_all_lambda_models": false}
		if accountErr == nil {
			configuration["account_concurrency"] = accountSettings
		} else {
			configuration["account_concurrency"] = nil
		}
		aliases, err := r.list(ctx, "ListAliases", path+"/aliases", "Aliases", url.Values{"MaxItems": {"50"}})
		normalizedAliases := []model.Document{}
		if err != nil {
			coverage = append(coverage, model.Document{"source": "ListAliases", "status": "UNAVAILABLE"})
		} else {
			for _, a := range aliases {
				abase, aq, err := lambdacost.FunctionARN(s, model.String(a, "AliasArn"))
				if err != nil || abase != base || aq != model.String(a, "Name") {
					return out, lambdacost.ErrEvidence
				}
				normalizedAliases = append(normalizedAliases, model.Document{"alias_arn": a["AliasArn"], "name": a["Name"], "function_version": a["FunctionVersion"], "routing_weights": lambdacost.Document(a["RoutingConfig"])["AdditionalVersionWeights"], "revision_id": a["RevisionId"]})
			}
		}
		configuration["aliases"] = normalizedAliases
		options := []struct{ action, path, key, field string }{{"ListProvisionedConcurrencyConfigs", "/2019-09-30/functions/" + url.PathEscape(base) + "/provisioned-concurrency", "ProvisionedConcurrencyConfigs", "provisioned_concurrency"}, {"ListEventSourceMappings", "/2015-03-31/event-source-mappings/", "EventSourceMappings", "event_source_mappings"}, {"ListFunctionEventInvokeConfigs", "/2019-09-25/functions/" + url.PathEscape(base) + "/event-invoke-config/list", "FunctionEventInvokeConfigs", "async_configurations"}, {"ListFunctionUrlConfigs", "/2021-10-31/functions/" + url.PathEscape(base) + "/urls", "FunctionUrlConfigs", "function_urls"}}
		for _, option := range options {
			query := url.Values{"MaxItems": {"50"}}
			if option.action == "ListEventSourceMappings" {
				query.Set("FunctionName", base)
			}
			rows, err := r.list(ctx, option.action, option.path, option.key, query)
			if err != nil {
				configuration[option.field] = nil
				coverage = append(coverage, model.Document{"source": option.action, "status": "UNAVAILABLE", "missing_is_zero": false})
				continue
			}
			for _, row := range rows {
				if target := model.String(row, "FunctionArn"); target != "" {
					b, _, err := lambdacost.FunctionARN(s, target)
					if err != nil || b != base {
						return out, lambdacost.ErrEvidence
					}
				}
			}
			configuration[option.field] = rows
			coverage = append(coverage, model.Document{"source": option.action, "status": "COMPLETE_PAGINATION_NON_ATOMIC", "missing_is_zero": false})
		}
		conc, err := r.get(ctx, "GetFunctionConcurrency", "/2017-10-31/functions/"+url.PathEscape(base)+"/concurrency", url.Values{})
		if err != nil {
			configuration["reserved_concurrency"] = nil
			coverage = append(coverage, model.Document{"source": "GetFunctionConcurrency", "status": "UNAVAILABLE"})
		} else {
			configuration["reserved_concurrency"] = conc["ReservedConcurrentExecutions"]
			configuration["reserved_concurrency_semantics"] = "CAPACITY_ISOLATION_NOT_PAID_IDLE_COMPUTE"
		}
		tags, err := r.get(ctx, "ListTags", "/2017-03-31/tags/"+url.PathEscape(base), url.Values{})
		if err != nil {
			configuration["tags"] = nil
			coverage = append(coverage, model.Document{"source": "ListTags", "status": "UNAVAILABLE"})
		} else {
			configuration["tags"] = tags["Tags"]
		}
		configuration["coverage"] = coverage
		configuration["last_seen_at"] = model.Now()
		out.Functions = append(out.Functions, model.Document{"provider": "AWS", "resource_type": "LAMBDA_FUNCTION", "provider_resource_id": base, "account_id": s.AccountID, "region": s.Region, "name": name, "state": configuration["state"], "lambda_configuration": configuration, "eligibility": "OBSERVE_ONLY"})
	}
	out.NextMarker = model.String(page, "NextMarker")
	if len(out.NextMarker) > 4096 || out.NextMarker != "" && out.NextMarker == sel.Marker {
		return out, lambdacost.ErrEvidence
	}
	out.Complete = out.NextMarker == ""
	out.Coverage = append(out.Coverage, model.Document{"source": "ListFunctions", "scope": "EVENT_FUNCTIONS_ONLY", "status": "BOUNDED_PAGINATED_NON_ATOMIC", "page_function_count": len(functions), "complete": out.Complete, "web_functions": "NOT_COLLECTED_SEPARATE_API"})
	out.Evidence = r.evidence()
	return out, nil
}
