package com.mohnish.signedchat.lab;

import org.springframework.web.bind.annotation.*;
import java.security.GeneralSecurityException;
import java.util.Map;

@RestController
@RequestMapping("/api/labs")
public class ExperimentController {
    private final ExperimentService experiments;
    public ExperimentController(ExperimentService experiments) { this.experiments = experiments; }
    @PostMapping public Map<String, Object> create() throws GeneralSecurityException { return experiments.create(); }
    @GetMapping("/{id}") public Map<String, Object> state(@PathVariable String id) { return experiments.state(id); }
    @DeleteMapping("/{id}") public void delete(@PathVariable String id) { experiments.delete(id); }
    @PostMapping("/{id}/prepare") public ExperimentService.Package prepare(@PathVariable String id, @RequestBody ExperimentService.Prepare request) { return experiments.prepare(id, request); }
    @PostMapping("/{id}/sign") public ExperimentService.Package sign(@PathVariable String id, @RequestBody ExperimentService.Sign request) throws GeneralSecurityException { return experiments.sign(id, request); }
    @PostMapping("/{id}/verify") public ExperimentService.Result verify(@PathVariable String id, @RequestBody ExperimentService.Check request) throws GeneralSecurityException { return experiments.verify(id, request); }
    @PostMapping("/{id}/deliver") public ExperimentService.Result deliver(@PathVariable String id, @RequestBody ExperimentService.Delivery request) throws GeneralSecurityException { return experiments.deliver(id, request); }
    @PostMapping("/{id}/trust") public void trust(@PathVariable String id, @RequestBody ExperimentService.Trust request) throws GeneralSecurityException { experiments.trust(id, request); }
    @PostMapping("/{id}/inbox/{deliveryId}") public void edit(@PathVariable String id, @PathVariable String deliveryId, @RequestBody ExperimentService.Package packet) { experiments.edit(id, deliveryId, packet); }
}
