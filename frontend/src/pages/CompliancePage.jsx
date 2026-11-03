import React, { useEffect, useState } from 'react';
import { FileCheck2, CheckCircle2, XCircle, AlertTriangle, Download, Info } from 'lucide-react';
import apiClient from '../api/client';

export default function CompliancePage() {
  const [data, setData] = useState(null);
  const [activeFramework, setActiveFramework] = useState('ISO_27001');
  const [editingControlId, setEditingControlId] = useState(null);
  const [evidenceInput, setEvidenceInput] = useState('');
  const [artifactInput, setArtifactInput] = useState('');
  const [message, setMessage] = useState(null);

  const fetchCompliance = async () => {
    try {
      const res = await apiClient.get('/compliance/frameworks');
      setData(res.data);
    } catch (err) {
      console.error('Error loading compliance controls:', err);
    }
  };

  useEffect(() => {
    fetchCompliance();
  }, []);

  const handleSaveEvidence = async (controlId) => {
    try {
      await apiClient.patch(`/compliance/controls/${controlId}`, {
        evidenceNotes: evidenceInput,
        artifactName: artifactInput || undefined
      });
      setEditingControlId(null);
      setArtifactInput('');
      setMessage('Compliance evidence & attestation saved to audit history.');
      await fetchCompliance();
    } catch (err) {
      console.error('Failed to update compliance control:', err);
    }
  };

  const handleExportReport = async () => {
    try {
      const res = await apiClient.get('/compliance/export-report');
      const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `AegisCloud-Compliance-Report-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  if (!data) {
    return <div className="p-6 text-xs text-slate-400">Evaluating ISO/IEC 27001 &amp; SOC 2 controls...</div>;
  }

  const filteredControls = (data.controls || []).filter((c) => c.framework === activeFramework);
  const isoSummary = data.summaries.ISO_27001;
  const soc2Summary = data.summaries.SOC_2;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Continuous Compliance & Evidence Management (GRC)</h2>
          <p className="text-sm text-slate-400">
            Automated technical control verification and evidence tracking for ISO/IEC 27001:2022 and SOC 2 Trust Services Criteria
          </p>
        </div>
        <button
          onClick={handleExportReport}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition"
        >
          <Download className="w-4 h-4" />
          Export Auditor Evidence Package (JSON)
        </button>
      </div>

      {/* Formal Audit Disclaimer */}
      <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center gap-3 text-xs text-slate-300">
        <Info className="w-4 h-4 text-cyan-400 shrink-0" />
        <span>{data.disclaimer}</span>
      </div>

      {message && (
        <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-xs text-emerald-200 flex justify-between">
          <span>{message}</span>
          <button onClick={() => setMessage(null)}>✕</button>
        </div>
      )}

      {/* Framework Selector Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div
          onClick={() => setActiveFramework('ISO_27001')}
          className={`cursor-pointer p-5 rounded-xl border transition ${
            activeFramework === 'ISO_27001'
              ? 'bg-slate-900 border-cyan-500 shadow-lg'
              : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-bold text-white text-base">ISO/IEC 27001:2022 (Annex A Controls)</h3>
            <span className="text-2xl font-extrabold text-emerald-400">{isoSummary.readinessPercentage}%</span>
          </div>
          <p className="text-xs text-slate-400">
            {isoSummary.passing} Passing • {isoSummary.failing} Failing • {isoSummary.partial} Partial ({isoSummary.total} Monitored Controls)
          </p>
        </div>

        <div
          onClick={() => setActiveFramework('SOC_2')}
          className={`cursor-pointer p-5 rounded-xl border transition ${
            activeFramework === 'SOC_2'
              ? 'bg-slate-900 border-cyan-500 shadow-lg'
              : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-bold text-white text-base">SOC 2 (Trust Services Criteria CC6 / CC7)</h3>
            <span className="text-2xl font-extrabold text-cyan-400">{soc2Summary.readinessPercentage}%</span>
          </div>
          <p className="text-xs text-slate-400">
            {soc2Summary.passing} Passing • {soc2Summary.failing} Failing • {soc2Summary.partial} Partial ({soc2Summary.total} Monitored Controls)
          </p>
        </div>
      </div>

      {/* Controls Checklist & Linked Findings */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 className="font-semibold text-white text-sm flex items-center gap-2">
          <FileCheck2 className="w-4 h-4 text-cyan-400" />
          {activeFramework === 'ISO_27001' ? 'ISO/IEC 27001:2022' : 'SOC 2'} Automated Control Matrix
        </h3>

        <div className="space-y-3">
          {filteredControls.map((ctrl) => (
            <div key={ctrl.id} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono font-bold text-xs">
                      {ctrl.control_code}
                    </span>
                    <h4 className="font-bold text-white text-sm">{ctrl.title}</h4>
                    <span className="text-[11px] text-slate-500">({ctrl.category})</span>
                  </div>
                  <p className="text-xs text-slate-400">{ctrl.description}</p>
                </div>

                <div className="flex items-center gap-2">
                  {ctrl.status === 'PASSING' ? (
                    <span className="flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-xs font-bold">
                      <CheckCircle2 className="w-3.5 h-3.5" /> PASSING
                    </span>
                  ) : ctrl.status === 'FAILING' ? (
                    <span className="flex items-center gap-1 px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 text-xs font-bold">
                      <XCircle className="w-3.5 h-3.5" /> FAILING ({ctrl.failing_assets_count} Violations)
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 px-2.5 py-1 rounded bg-amber-500/20 text-amber-300 text-xs font-bold">
                      <AlertTriangle className="w-3.5 h-3.5" /> PARTIAL
                    </span>
                  )}

                  <button
                    onClick={() => {
                      setEditingControlId(ctrl.id);
                      setEvidenceInput(ctrl.evidence_notes || '');
                    }}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200"
                  >
                    Attach Evidence
                  </button>
                </div>
              </div>

              {/* Linked Technical Findings */}
              {ctrl.linked_findings && ctrl.linked_findings.length > 0 && (
                <div className="p-3 rounded-lg bg-rose-950/30 border border-rose-500/30 space-y-1.5">
                  <p className="text-[11px] font-semibold text-rose-300">
                    Failing Technical Assets Linked to {ctrl.control_code} (Remediate to restore PASSING status):
                  </p>
                  {ctrl.linked_findings.map((f) => (
                    <div key={f.id} className="text-xs text-slate-300 flex items-center justify-between">
                      <span>• [{f.severity}] {f.title}</span>
                      <span className="font-mono text-slate-400">{f.affected_asset}</span>
                    </div>
                  ))}
                </div>
              )}

              <div className="text-xs text-slate-400 flex items-center justify-between pt-1 border-t border-slate-900">
                <span>Evidence Note: <strong className="text-slate-300">{ctrl.evidence_notes}</strong></span>
                <span>Evaluated: {new Date(ctrl.last_evaluated_at).toLocaleTimeString()}</span>
              </div>

              {editingControlId === ctrl.id && (
                <div className="pt-2 space-y-2 border-t border-slate-800">
                  <input
                    type="text"
                    value={evidenceInput}
                    onChange={(e) => setEvidenceInput(e.target.value)}
                    placeholder="Enter compliance auditor evidence note..."
                    className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-xs text-white"
                  />
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={artifactInput}
                      onChange={(e) => setArtifactInput(e.target.value)}
                      placeholder="Optional Evidence Artifact Filename (e.g. IAM_Quarterly_Review_Q4.pdf)"
                      className="flex-1 px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-xs text-white"
                    />
                    <button
                      onClick={() => handleSaveEvidence(ctrl.id)}
                      className="px-3 py-1.5 rounded bg-cyan-500 text-slate-950 font-semibold text-xs"
                    >
                      Save Evidence
                    </button>
                    <button
                      onClick={() => setEditingControlId(null)}
                      className="px-3 py-1.5 rounded bg-slate-800 text-slate-300 text-xs"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
