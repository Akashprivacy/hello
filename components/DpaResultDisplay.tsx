
import React, { useState, useMemo } from 'react';
import type { DpaAnalysisResult, DpaPerspective, RiskLevel } from '../types';
import { AlertOctagonIcon, CheckCircleIcon, ShieldExclamationIcon } from './Icons';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';


const getRiskStyle = (riskLevel: RiskLevel) => {
    switch (riskLevel) {
        case 'High': return { color: 'text-red-600 dark:text-red-400', borderColor: 'border-red-500/30 dark:border-red-500/50', bgColor: 'bg-red-50 dark:bg-red-900/20', icon: <ShieldExclamationIcon className="h-6 w-6" />, badgeBg: 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-200', fill: 'hsl(0, 72%, 51%)' };
        case 'Medium': return { color: 'text-orange-600 dark:text-orange-400', borderColor: 'border-orange-500/30 dark:border-orange-500/50', bgColor: 'bg-orange-50 dark:bg-orange-900/20', icon: <AlertOctagonIcon className="h-6 w-6" />, badgeBg: 'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-200', fill: 'hsl(32, 95%, 54%)' };
        case 'Low': return { color: 'text-green-600 dark:text-green-400', borderColor: 'border-green-500/30 dark:border-green-500/50', bgColor: 'bg-green-50 dark:bg-green-900/20', icon: <CheckCircleIcon className="h-6 w-6" />, badgeBg: 'bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-200', fill: 'hsl(145, 63%, 42%)' };
        default: return { color: 'text-slate-600 dark:text-slate-400', borderColor: 'border-slate-300 dark:border-slate-700', bgColor: 'bg-slate-100 dark:bg-slate-800/50', icon: <CheckCircleIcon className="h-6 w-6" />, badgeBg: 'bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300', fill: 'hsl(220, 10%, 50%)' };
    }
};

const OverallRiskCard: React.FC<{ level: RiskLevel, summary: string }> = ({ level, summary }) => {
  const { color, borderColor, bgColor, icon } = getRiskStyle(level);
  return (
    <div className={`p-6 rounded-lg border ${borderColor} ${bgColor} flex items-start gap-4`}>
        <div className={`flex-shrink-0 ${color}`}>{icon}</div>
        <div>
            <h4 className={`text-lg font-bold ${color}`}>{level} Risk Profile</h4>
            <p className="mt-1 text-sm text-[var(--text-primary)]">{summary}</p>
        </div>
    </div>
  )
}

const ClauseRiskChart: React.FC<{ analysis: DpaAnalysisResult['analysis']}> = ({ analysis }) => {
    const riskCounts = useMemo(() => {
        const counts = { High: 0, Medium: 0, Low: 0, Unknown: 0 };
        analysis.forEach(item => {
            counts[item.riskLevel] = (counts[item.riskLevel] || 0) + 1;
        });
        return [
            { name: 'High Risk', count: counts.High, fill: getRiskStyle('High').fill },
            { name: 'Medium Risk', count: counts.Medium, fill: getRiskStyle('Medium').fill },
            { name: 'Low Risk', count: counts.Low, fill: getRiskStyle('Low').fill },
        ].filter(item => item.count > 0);
    }, [analysis]);

    if (riskCounts.length === 0) return null;

    return (
        <div className="h-48 w-full">
            <ResponsiveContainer>
                <BarChart data={riskCounts} layout="vertical" margin={{ top: 5, right: 20, left: 20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" horizontal={false} />
                    <XAxis type="number" allowDecimals={false} tick={{ fill: 'var(--text-primary)', fontSize: 12 }} />
                    <YAxis type="category" dataKey="name" width={80} tick={{ fill: 'var(--text-primary)', fontSize: 12 }} />
                    <Tooltip 
                         contentStyle={{ 
                            backgroundColor: 'var(--bg-tertiary)', 
                            border: '1px solid var(--border-primary)', 
                            borderRadius: '0.5rem',
                        }} 
                    />
                    <Bar dataKey="count" name="Number of Clauses" background={{ fill: 'var(--bg-tertiary)' }} />
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
};


const ClauseAnalysisCard: React.FC<{ clause: any }> = ({ clause }) => {
  const [isOpen, setIsOpen] = useState(false);
  const { badgeBg, color } = getRiskStyle(clause.riskLevel);
  return (
    <div className="bg-[var(--bg-secondary)] rounded-lg border border-[var(--border-primary)] shadow-sm overflow-hidden transition-all duration-300">
        <button onClick={() => setIsOpen(!isOpen)} className="w-full flex items-center justify-between p-4 text-left" aria-expanded={isOpen}>
            <div className="flex items-center gap-4 flex-1 min-w-0">
                 <span className={`flex-shrink-0 inline-flex items-center justify-center rounded-full px-3 py-1 text-xs font-bold w-24 ${badgeBg}`}>
                    {clause.riskLevel} Risk
                </span>
                <h4 className="font-semibold text-md text-[var(--text-headings)] truncate">{clause.clause}</h4>
            </div>
            <svg className={`w-5 h-5 text-[var(--text-primary)] transform transition-transform duration-200 ml-4 ${isOpen ? 'rotate-180' : 'rotate-0'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
            </svg>
        </button>
        {isOpen && (
            <div className="px-5 pb-5 pt-2 border-t border-[var(--border-primary)] animate-fade-in-up space-y-5">
                <div>
                  <h5 className="font-semibold text-[var(--text-headings)] text-sm">Summary</h5>
                  <p className="text-[var(--text-primary)] text-sm mt-1">{clause.summary}</p>
                </div>
                <div className={`p-4 rounded-md border ${getRiskStyle(clause.riskLevel).borderColor} ${getRiskStyle(clause.riskLevel).bgColor}`}>
                  <h5 className={`font-semibold ${color} text-sm`}>Risk Analysis</h5>
                  <p className={`text-sm mt-1 ${color} opacity-90`}>{clause.risk}</p>
                </div>
                <div className="p-4 rounded-md bg-green-50 dark:bg-green-900/20 border border-green-500/20">
                  <h5 className="font-semibold text-green-800 dark:text-green-300 text-sm">Recommendation</h5>
                  <p className="text-green-700 dark:text-green-300/90 text-sm mt-1">{clause.recommendation}</p>
                </div>
            </div>
        )}
    </div>
  )
}


export const DpaResultDisplay: React.FC<{ result: DpaAnalysisResult; perspective: DpaPerspective }> = ({ result, perspective }) => {
  const perspectiveText = perspective === 'controller' ? 'Data Controller' : 'Data Processor';
  
  return (
    <div className="max-w-5xl mx-auto animate-fade-in-up">
      <div className="mb-8 text-center">
        <h3 className="text-2xl font-bold text-[var(--text-headings)]">DPA Analysis Dashboard</h3>
        <p className="text-[var(--text-primary)] mt-1">
          Analyzed from the perspective of a <span className="font-semibold text-brand-blue">{perspectiveText}</span>.
        </p>
      </div>
      
      <div className="space-y-8">
        <OverallRiskCard level={result.overallRisk.level} summary={result.overallRisk.summary} />
        
        <div className="bg-[var(--bg-secondary)] rounded-lg border border-[var(--border-primary)] shadow-sm p-5">
            <h4 className="text-xl font-bold text-[var(--text-headings)] mb-4 text-center">Clause Risk Breakdown</h4>
            <ClauseRiskChart analysis={result.analysis} />
        </div>

        <div>
            <h4 className="text-xl font-bold text-[var(--text-headings)] mb-4">Detailed Clause Analysis</h4>
            <div className="space-y-4">
                {result.analysis.map((clause, index) => (
                    <ClauseAnalysisCard key={index} clause={clause} />
                ))}
            </div>
        </div>
      </div>
    </div>
  );
};