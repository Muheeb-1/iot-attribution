"""
VERIFICATION PROTOTYPE - IoT Incident Attribution
=================================================
Built and run on 23 Aug 2026 to prove the design produces a real result
BEFORE any code is written for the real project.

What it does:
  1. Invents a fake office network of 7 IoT devices with 6 hours of normal traffic
  2. Injects an attack starting from a RANDOMLY CHOSEN device, spreading to 2 more
  3. Detects which devices went abnormal, and when
  4. Works out which one STARTED it, using a causal-chain method
  5. Scores itself against the true answer, and against 4 standard approaches

Measured result over 50 runs (see README):
  ranking by traffic volume   -> right 10% of the time
  ranking by earliest onset   -> right 54% of the time
  this causal method          -> right 90% of the time

Run it:
  pip install pandas numpy scikit-learn networkx
  python sim.py 50

This is a SINGLE-FILE proof, not the project. The real project splits this
into src/generate.py, src/features.py, src/detect.py, src/attribute.py and
src/evaluate.py, adds the LLM report layer and a dashboard, and later reads
real captured traffic instead of invented traffic. Use this to check that
what you build matches what was verified.
"""
import random, numpy as np, pandas as pd, networkx as nx
from sklearn.ensemble import IsolationForest

WIN = 60
BASELINE_H = 3
TOTAL_H = 6
SERVER = "server"
CLOUD = {"cam": "cloud_cam", "plug": "cloud_plug", "lap": "cloud_web"}
C2 = "ext_c2"

DEVICES = [
    ("esp32-01","sensor"), ("esp32-02","sensor"), ("esp32-03","sensor"),
    ("camera","cam"), ("plug","plug"), ("laptop-c","lap"), ("laptop-d","lap"),
]
NAMES = [d for d,_ in DEVICES]

def normal_traffic(rng):
    rows=[]; T=TOTAL_H*3600
    for dev,kind in DEVICES:
        if kind=="sensor":
            t=rng.uniform(0,10)
            while t<T:
                rows.append((t,dev,SERVER,int(rng.normal(214,18)),int(rng.normal(60,8)),2))
                t+=10*rng.uniform(0.96,1.04)
        elif kind=="cam":
            t=rng.uniform(0,5)
            while t<T:
                rows.append((t,dev,CLOUD["cam"],int(rng.normal(240000,20000)),int(rng.normal(4500,600)),40))
                t+=5.0*rng.uniform(0.9,1.1)
        elif kind=="plug":
            t=rng.uniform(0,60)
            while t<T:
                rows.append((t,dev,CLOUD["plug"],int(rng.normal(1200,200)),int(rng.normal(400,60)),4))
                t+=60*rng.uniform(0.9,1.1)
        else:
            t=rng.uniform(0,30)
            while t<T:
                for _ in range(int(rng.integers(1,6))):
                    rows.append((t,dev,CLOUD["lap"],int(abs(rng.normal(9000,6000))+500),
                                 int(abs(rng.normal(40000,30000))+1000),12))
                t+=30*rng.uniform(0.5,2.0)
        for _ in range(int(rng.integers(3,9))):
            rows.append((rng.uniform(0,T),dev,f"upd_{rng.integers(0,40)}",
                         int(abs(rng.normal(3000,1500))+200),int(abs(rng.normal(8000,4000))+500),6))
    return rows

def inject_attack(rows,rng):
    T=TOTAL_H*3600
    cands=list(NAMES)
    origin=cands[int(rng.integers(0,len(cands)))]
    rest=[d for d in cands if d!=origin]; rng.shuffle(rest)
    v2,v3=rest[0],rest[1]
    t0=rng.uniform(BASELINE_H*3600+1800,T-3600)
    t=t0
    while t<T:
        rows.append((t,origin,C2,int(rng.normal(200,20)),int(rng.normal(120,15)),2))
        t+=30*rng.uniform(0.87,1.13)
    ts=t0+90
    for peer in cands:
        if peer==origin: continue
        for k in range(4): rows.append((ts+k*0.4+rng.uniform(0,.2),origin,peer,60,0,1))
    tb=t0+180
    for k in range(340): rows.append((tb+k*0.26,origin,v2,int(rng.normal(420,40)),int(rng.normal(300,40)),3))
    t2=t0+270; t=t2
    while t<T:
        rows.append((t,v2,C2,int(rng.normal(200,20)),int(rng.normal(120,15)),2))
        t+=30*rng.uniform(0.87,1.13)
    te=t2+30
    for k in range(700): rows.append((te+k*0.35,v2,C2,int(rng.normal(480000,40000)),1200,340))
    t3=t0+420
    for k in range(900): rows.append((t3+k*0.13,v2,v3,int(rng.normal(700,80)),int(rng.normal(2500,400)),5))
    return rows,{"origin":origin,"chain":[origin,v2,v3],"onsets":{origin:t0,v2:t2,v3:t3}}

def make_run(seed):
    rng=np.random.default_rng(seed)
    rows=normal_traffic(rng)
    rows,truth=inject_attack(rows,rng)
    df=pd.DataFrame(rows,columns=["t","src","dst","bytes_out","bytes_in","pkts"])
    return df.sort_values("t").reset_index(drop=True),truth

def features(df):
    df=df.copy(); df["w"]=(df["t"]//WIN).astype(int)
    base_w=BASELINE_H*3600//WIN
    seen={d:set(df[(df.src==d)&(df.w<base_w)].dst.unique()) for d in NAMES}
    out=[]
    for (dev,w),g in df.groupby(["src","w"],sort=True):
        if dev not in NAMES: continue
        dsts=set(g.dst.unique()); ts=np.sort(g.t.values); iat=np.diff(ts)
        cv=(iat.std()/iat.mean()) if len(iat)>3 and iat.mean()>0 else 1.0
        out.append(dict(dev=dev,w=w,bytes_out=g.bytes_out.sum(),bytes_in=g.bytes_in.sum(),
            n_conn=len(g),n_dst=len(dsts),n_new_dst=len(dsts-seen[dev]),
            n_peer=int(g.dst.isin(NAMES).sum()),iat_reg=1.0/(cv+0.05)))
    return pd.DataFrame(out)

FEATS=["bytes_out","bytes_in","n_conn","n_dst","n_new_dst","n_peer","iat_reg"]

def detect(F,thresh=4.0,k=3):
    base_w=BASELINE_H*3600//WIN; scores={}; onsets={}
    for dev,g in F.groupby("dev"):
        g=g.sort_values("w"); b=g[g.w<base_w]
        if len(b)<10: continue
        med=b[FEATS].median(); mad=(b[FEATS]-med).abs().median()*1.4826
        mad=mad.replace(0,np.nan).fillna(b[FEATS].std().replace(0,1)).clip(lower=1e-6)
        z=((g[FEATS]-med).abs()/mad).max(axis=1).values
        try:
            iso=IsolationForest(n_estimators=60,random_state=0).fit(b[FEATS])
            s2=-iso.score_samples(g[FEATS]); s2=(s2-s2[:len(b)].mean())/(s2[:len(b)].std()+1e-9)
        except Exception:
            s2=np.zeros(len(g))
        s=np.maximum(z,s2*1.5); ws=g.w.values
        scores[dev]=dict(zip(ws.tolist(),s.tolist())); on=None
        for i in range(len(s)-k+1):
            if ws[i]<base_w: continue
            if all(s[i+j]>thresh for j in range(k)): on=float(ws[i]*WIN); break
        if on is not None: onsets[dev]=on
    return scores,onsets

def attribute(df,onsets,dmax=1800):
    devs=list(onsets)
    if not devs: return [],0.0,[]
    G=nx.DiGraph(); G.add_nodes_from(devs)
    for u in devs:
        for v in devs:
            if u==v or not (onsets[u]<onsets[v]<=onsets[u]+dmax): continue
            m=df[(df.src==u)&(df.dst==v)&(df.t>=onsets[u])&(df.t<=onsets[v])]
            if len(m)>0: G.add_edge(u,v,w=len(m))
    base_w=BASELINE_H*3600//WIN
    tmin,tmax=min(onsets.values()),max(onsets.values()); span=max(tmax-tmin,1)
    S={}
    for d in devs:
        reach=len(nx.descendants(G,d))/max(len(devs)-1,1)
        orphan=1.0 if G.in_degree(d)==0 else 0.0
        early=(tmax-onsets[d])/span
        post=df[(df.src==d)&(df.t>=onsets[d])]
        pre=set(df[(df.src==d)&(df.t<base_w*WIN)].dst.unique())
        nov=(len(set(post.dst.unique())-pre)/max(len(set(post.dst.unique())),1)) if len(post) else 0
        S[d]=0.40*reach+0.30*orphan+0.15*early+0.15*nov
    ranked=sorted(S,key=lambda d:-S[d])
    for d in ranked[:3]:
        H=G.copy(); H.remove_edges_from(list(G.out_edges(d)))
        roots=[n for n in H if H.in_degree(n)==0]
        unexp=len([n for n in H if not any(nx.has_path(H,r,n) for r in roots)])
        S[d]+=0.05*unexp
    ranked=sorted(S,key=lambda d:-S[d])
    conf=(S[ranked[0]]-S[ranked[1]])/max(S[ranked[0]],1e-9) if len(ranked)>1 else 1.0
    path=[ranked[0]]+[n for n in nx.bfs_tree(G,ranked[0]) if n!=ranked[0]] if ranked[0] in G else ranked[:1]
    return ranked,conf,path

def baselines(df,onsets,scores):
    tot=df[df.src.isin(NAMES)].groupby("src").bytes_out.sum()
    nc=df[df.src.isin(NAMES)].groupby("src").size()
    return {"B1 total bytes":list(tot.sort_values(ascending=False).index),
            "B2 anomaly score":sorted(scores,key=lambda d:-max(scores[d].values())) if scores else [],
            "B3 connection count":list(nc.sort_values(ascending=False).index),
            "B4 earliest onset":sorted(onsets,key=lambda d:onsets[d]) if onsets else []}

def rank_of(l,x): return l.index(x)+1 if x in l else 99

if __name__=="__main__":
    import sys
    N=int(sys.argv[1]) if len(sys.argv)>1 else 30
    M=["B1 total bytes","B2 anomaly score","B3 connection count","B4 earliest onset","OURS causal"]
    res={m:[] for m in M}; abst=0; missed=0
    for i in range(N):
        df,truth=make_run(1000+i); F=features(df); scores,onsets=detect(F)
        if truth["origin"] not in onsets: missed+=1
        ranked,conf,path=attribute(df,onsets); b=baselines(df,onsets,scores)
        for m in M[:4]: res[m].append(rank_of(b[m],truth["origin"]))
        res["OURS causal"].append(rank_of(ranked,truth["origin"]))
        if conf<0.15: abst+=1
        if i==0:
            print(f"  sample run  true origin = {truth['origin']}   true chain = {' -> '.join(truth['chain'])}")
            print(f"              ours top-3  = {ranked[:3]}   confidence = {conf:.2f}")
            print(f"              recovered path = {' -> '.join(path)}")
            print(f"              onsets detected = { {k: int(v) for k,v in sorted(onsets.items(), key=lambda x:x[1])} }")
    print(f"\n  runs = {N}    origin never flagged by detector: {missed}    abstained: {abst}\n")
    print(f"  {'method':<24}{'top-1':>8}{'top-3':>8}{'mean rank':>12}")
    print("  "+"-"*52)
    for m in M:
        r=np.array(res[m]); ok=r[r<99]
        print(f"  {m:<24}{(r==1).mean()*100:>7.0f}%{(r<=3).mean()*100:>7.0f}%{(ok.mean() if len(ok) else float('nan')):>12.2f}")
