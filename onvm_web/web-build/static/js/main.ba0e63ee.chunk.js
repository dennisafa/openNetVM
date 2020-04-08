(window.webpackJsonp = window.webpackJsonp || []).push([
  [0],
  {
    23: function(e, t, n) {
      e.exports = n(41);
    },
    28: function(e, t, n) {},
    39: function(e, t, n) {},
    41: function(e, t, n) {
      "use strict";
      n.r(t);
      var a = n(0),
        o = n.n(a),
        r = n(18),
        l = n.n(r),
        c = (n(28), n(42)),
        s = n(44),
        i = n(34),
        u = n(43),
        p = n(4),
        m = n(5),
        h = n(7),
        f = n(6),
        b = n(8),
        v = n(46),
        d = n(45),
        g = n(1),
        E = n(10),
        y = {},
        O = {},
        C = [],
        L = 0,
        j = null,
        N = -1;
      function k(e, t, n) {
        var a = {
          name: e,
          callback: t,
          includePastEvents: n,
          hasBeenCalled: !1
        };
        if (n && j) {
          var o = j;
          console.log("Catching event subscriber up to all past events.");
          for (var r = 0; r !== N + 1; ) a.callback(o[r]), ++r;
          a.hasBeenCalled = !0;
        }
        C.push(a);
      }
      function w(e) {
        C = C.filter(function(t) {
          return t.name !== e;
        });
      }
      function x(e, t) {
        if (e.length < t) return e;
        var n = e[0];
        for (e = e.slice(2); e.length > t; ) e = e.slice(1);
        return [n].concat(Object(E.a)(e));
      }
      function D(e, t) {
        if ((e in O ? O[e].push(t) : (O[e] = [t]), e in y)) return y[e];
      }
      function P(e, t, n) {
        e in O &&
          (0 ===
            O[e].filter(function(e) {
              return e !== t;
            }).length && delete O[e],
          null != n && (y[e] = n));
      }
      var S = (function(e) {
          function t() {
            var e, n;
            Object(p.a)(this, t);
            for (var a = arguments.length, o = new Array(a), r = 0; r < a; r++)
              o[r] = arguments[r];
            return (
              ((n = Object(h.a)(
                this,
                (e = Object(f.a)(t)).call.apply(e, [this].concat(o))
              )).state = { interval: null }),
              n
            );
          }
          return (
            Object(b.a)(t, e),
            Object(m.a)(t, [
              {
                key: "dataFetcher",
                value: function() {
                  var e = window.location.hostname;
                  fetch("http://".concat(e, ":8000/onvm_json_stats.json"))
                    .then(function(e) {
                      return e.json();
                    })
                    .then(function(e) {
                      return (function(e) {
                        var t = e.onvm_nf_stats,
                          n = function(e) {
                            if (e in O)
                              O[e].forEach(function(n) {
                                return n(t[e], L);
                              });
                            else if (
                              (console.log(
                                "No NF Subscriber callback for label: " + e
                              ),
                              e in y)
                            ) {
                              var n = t[e],
                                a = y[e];
                              a[0].push(L),
                                (a[0] = x(a[0], 40)),
                                a[1].push(n.TX),
                                (a[1] = x(a[1], 40)),
                                a[2].push(n.RX),
                                (a[2] = x(a[2], 40));
                            } else
                              console.error(
                                "No NF Restore state for label: " + e
                              );
                          };
                        for (var a in t) n(a);
                        var o = e.onvm_port_stats,
                          r = function(e) {
                            if (e in O)
                              O[e].forEach(function(t) {
                                return t(o[e], L);
                              });
                            else if (
                              (console.log(
                                "No NF Subscriber callback for label: " + e
                              ),
                              e in y)
                            ) {
                              var t = o[e],
                                n = y[e];
                              n[0].push(L),
                                (n[0] = x(n[0], 40)),
                                n[1].push(t.TX),
                                (n[1] = x(n[1], 40)),
                                n[2].push(t.RX),
                                (n[2] = x(n[2], 40));
                            } else
                              console.error(
                                "No NF Restore state for label: " + e
                              );
                          };
                        for (var l in o) r(l);
                        ++L;
                      })(e);
                    })
                    .catch(function(e) {
                      return console.error(e);
                    }),
                    fetch("http://".concat(e, ":8000/onvm_json_events.json"))
                      .then(function(e) {
                        return e.json();
                      })
                      .then(function(e) {
                        return (function(e) {
                          for (
                            var t = function() {
                              var t = e[++N];
                              t &&
                                C.forEach(function(e) {
                                  return e.callback(t);
                                });
                            };
                            N < e.length - 1;

                          )
                            t();
                          j = e;
                        })(e);
                      })
                      .catch(function(e) {
                        return console.error(e);
                      });
                }
              },
              {
                key: "componentDidMount",
                value: function() {
                  var e = setInterval(this.dataFetcher, 3e3);
                  this.setState({ interval: e });
                }
              },
              {
                key: "componentWillUnmount",
                value: function() {
                  var e = this.state.interval;
                  e && clearInterval(e);
                }
              },
              {
                key: "render",
                value: function() {
                  var e = this.props.children,
                    t = {
                      itemsObjects: [
                        {
                          value: "NF Dashboard",
                          to: "/nfs",
                          icon: "home",
                          LinkComponent: Object(v.a)(d.a)
                        },
                        {
                          value: "Port Dashboard",
                          to: "/ports",
                          icon: "server",
                          LinkComponent: Object(v.a)(d.a)
                        },
                        {
                          value: "Core Mappings",
                          to: "/core-mappings",
                          icon: "cpu",
                          LinkComponent: Object(v.a)(d.a)
                        }
                      ]
                    };
                  return a.createElement(
                    g.f.Wrapper,
                    {
                      headerProps: {
                        href: "/",
                        alt: "openNetVM",
                        imageURL: "/onvm-logo.png"
                      },
                      navProps: t,
                      footerProps: {}
                    },
                    e
                  );
                }
              }
            ]),
            t
          );
        })(a.PureComponent),
        R = n(12),
        F = n(17),
        I = n.n(F),
        A = {
          x: { label: { text: "X Axis", position: "outer-center" } },
          y: { label: { text: "Y Axis", position: "outer-middle" } }
        },
        M = (function(e) {
          function t() {
            var e, n;
            Object(p.a)(this, t);
            for (var a = arguments.length, o = new Array(a), r = 0; r < a; r++)
              o[r] = arguments[r];
            return (
              ((n = Object(h.a)(
                this,
                (e = Object(f.a)(t)).call.apply(e, [this].concat(o))
              )).state = {
                graphData: {
                  xs: {
                    tx_pps: "".concat(n.props.nfLabel, "x1"),
                    rx_pps: "".concat(n.props.nfLabel, "x1")
                  },
                  names: { tx_pps: "TX PPS", rx_pps: "RX PPS" },
                  empty: { label: { text: "No Data to Display" } },
                  columns: [
                    ["".concat(n.props.nfLabel, "x1")],
                    ["tx_pps"],
                    ["rx_pps"]
                  ]
                }
              }),
              (n.dataCallback = function(e, t) {
                var a = Object(R.a)({}, n.state.graphData),
                  o = a.columns;
                o[0].push(t),
                  (o[0] = n.trimToSize(o[0], 40)),
                  o[1].push(e.TX),
                  (o[1] = n.trimToSize(o[1], 40)),
                  o[2].push(e.RX),
                  (o[2] = n.trimToSize(o[2], 40)),
                  n.setState({ graphData: a });
              }),
              (n.trimToSize = function(e, t) {
                if (e.length < t) return e;
                var n = e[0];
                for (e = e.slice(2); e.length > t; ) e = e.slice(1);
                return [n].concat(Object(E.a)(e));
              }),
              n
            );
          }
          return (
            Object(b.a)(t, e),
            Object(m.a)(t, [
              {
                key: "componentDidMount",
                value: function() {
                  console.log("Graph Mount: " + this.props.nfLabel);
                  var e = "NF ".concat(this.props.nfLabel.split(" - ")[1]);
                  "Port" === this.props.nfLabel.substring(0, 4) &&
                    (e = this.props.nfLabel);
                  var t = D(e, this.dataCallback);
                  if (t) {
                    console.log("Graph Restore: " + this.props.nfLabel);
                    var n = Object(R.a)({}, this.state.graphData);
                    (n.columns = t), this.setState({ graphData: n });
                  }
                }
              },
              {
                key: "componentWillUnmount",
                value: function() {
                  console.log("Graph Unmount: " + this.props.nfLabel);
                  var e = "NF ".concat(this.props.nfLabel.split(" - ")[1]);
                  "Port" === this.props.nfLabel.substring(0, 4) &&
                    (e = this.props.nfLabel),
                    P(e, this.dataCallback, this.state.graphData.columns);
                }
              },
              {
                key: "render",
                value: function() {
                  var e = this,
                    t =
                      null === this.props.showMoreInfoButton ||
                      void 0 === this.props.showMoreInfoButton ||
                      this.props.showMoreInfoButton,
                    n = this.props.extraContent;
                  return a.createElement(
                    g.c,
                    null,
                    a.createElement(
                      g.c.Header,
                      null,
                      a.createElement(g.c.Title, null, this.props.nfLabel),
                      t &&
                        a.createElement(
                          g.c.Options,
                          null,
                          a.createElement(
                            g.b,
                            {
                              RootComponent: "a",
                              color: "secondary",
                              size: "sm",
                              className: "ml-2",
                              onClick: function() {
                                var t = e.props.history;
                                t
                                  ? t.push("/nfs/".concat(e.props.nfLabel))
                                  : console.error(
                                      "Failed to go to single NF page"
                                    );
                              }
                            },
                            "View More Info"
                          )
                        )
                    ),
                    a.createElement(
                      g.c.Body,
                      null,
                      a.createElement(I.a, {
                        data: this.state.graphData,
                        axis: A,
                        legend: { show: !0 },
                        padding: { bottom: 0, top: 0 }
                      }),
                      n
                    )
                  );
                }
              }
            ]),
            t
          );
        })(a.PureComponent),
        _ = {
          x: { label: { text: "X Axis", position: "outer-center" } },
          y: { label: { text: "Y Axis", position: "outer-middle" } }
        },
        B = (function(e) {
          function t(e) {
            var n;
            return (
              Object(p.a)(this, t),
              ((n = Object(h.a)(this, Object(f.a)(t).call(this, e))).state = {
                graphData: {
                  xs: { usage: "".concat(n.label, "x1") },
                  names: { usage: "Usage PPS" },
                  empty: { label: { text: "No Data to Display" } },
                  columns: [["".concat(n.label, "x1")], ["usage"]]
                },
                label: "Core ".concat(n.props.coreNum)
              }),
              (n.dataCallback = function(e, t) {
                var a = Object(R.a)({}, n.state.graphData),
                  o = a.columns;
                o[0].push(t),
                  (o[0] = n.trimToSize(o[0], 40)),
                  o[1].push(e.Rusage.Core_CPU_Usages[n.props.coreNum]),
                  (o[1] = n.trimToSize(o[1], 40)),
                  n.setState({ graphData: a });
              }),
              (n.trimToSize = function(e, t) {
                if (e.length < t) return e;
                var n = e[0];
                for (e = e.slice(2); e.length > t; ) e = e.slice(1);
                return [n].concat(Object(E.a)(e));
              }),
              (n.label = "Core ".concat(e.coreNum)),
              n
            );
          }
          return (
            Object(b.a)(t, e),
            Object(m.a)(t, [
              {
                key: "componentDidMount",
                value: function() {
                  console.log("Graph Mount: " + this.label);
                  var e = D("NF 1", this.dataCallback);
                  if (e) {
                    console.log("Graph Restore: " + this.label);
                    var t = Object(R.a)({}, this.state.graphData);
                    (t.columns = e), this.setState({ graphData: t });
                  }
                }
              },
              {
                key: "componentWillUnmount",
                value: function() {
                  console.log("Graph Unmount: " + this.label),
                    P("NF 1", this.dataCallback, this.state.graphData.columns);
                }
              },
              {
                key: "render",
                value: function() {
                  var e = this,
                    t =
                      null === this.props.showMoreInfoButton ||
                      void 0 === this.props.showMoreInfoButton ||
                      this.props.showMoreInfoButton,
                    n = this.props.extraContent;
                  return a.createElement(
                    g.c,
                    null,
                    a.createElement(
                      g.c.Header,
                      null,
                      a.createElement(g.c.Title, null, this.label),
                      t &&
                        a.createElement(
                          g.c.Options,
                          null,
                          a.createElement(
                            g.b,
                            {
                              RootComponent: "a",
                              color: "secondary",
                              size: "sm",
                              className: "ml-2",
                              onClick: function() {
                                var t = e.props.history;
                                t
                                  ? t.push("/nfs/".concat(e.label))
                                  : console.error(
                                      "Failed to go to single NF page"
                                    );
                              }
                            },
                            "View More Info"
                          )
                        )
                    ),
                    a.createElement(
                      g.c.Body,
                      null,
                      a.createElement(I.a, {
                        data: this.state.graphData,
                        axis: _,
                        legend: { show: !0 },
                        padding: { bottom: 0, top: 0 }
                      }),
                      n
                    )
                  );
                }
              }
            ]),
            t
          );
        })(a.PureComponent),
        G = (function(e) {
          function t() {
            var e, n;
            Object(p.a)(this, t);
            for (var a = arguments.length, o = new Array(a), r = 0; r < a; r++)
              o[r] = arguments[r];
            return (
              ((n = Object(h.a)(
                this,
                (e = Object(f.a)(t)).call.apply(e, [this].concat(o))
              )).state = { nfLabelList: [] }),
              (n.eventHandler = function(e) {
                var t;
                console.log(e),
                  "NF Ready" === e.message &&
                    ((t = " - ".concat(e.source.instance_id)),
                    (t = "NF" === e.source.type ? "NF" + t : e.source.type + t),
                    n.setState(function(e) {
                      return {
                        nfLabelList: [t].concat(Object(E.a)(e.nfLabelList))
                      };
                    })),
                  "NF Stopping" === e.message &&
                    ((t = " - ".concat(e.source.instance_id)),
                    (t = "NF" === e.source.type ? "NF" + t : e.source.type + t),
                    console.log(t),
                    n.setState(function(e) {
                      console.log(e.nfLabelList);
                      var n = Object(E.a)(
                        e.nfLabelList.filter(function(e) {
                          return e.split(" - ")[1] !== t.split(" - ")[1];
                        })
                      );
                      return (
                        console.log("end: " + e.nfLabelList), { nfLabelList: n }
                      );
                    }));
              }),
              n
            );
          }
          return (
            Object(b.a)(t, e),
            Object(m.a)(t, [
              {
                key: "componentDidMount",
                value: function() {
                  k("NF DASHBOARD PAGE", this.eventHandler, !0);
                }
              },
              {
                key: "componentWillUnmount",
                value: function() {
                  w("NF DASHBOARD PAGE");
                }
              },
              {
                key: "render",
                value: function() {
                  var e = this.props.history,
                    t = this.state.nfLabelList;
                  return a.createElement(
                    g.e.Content,
                    null,
                    a.createElement(
                      g.d.Row,
                      null,
                      t.map(function(t) {
                        return a.createElement(
                          g.d.Col,
                          { md: 6, xl: 4, key: t },
                          a.createElement(M, { nfLabel: t, history: e })
                        );
                      }),
                      0 === t.length && "No Running NFS to Display!",
                      a.createElement(
                        g.d.Col,
                        { md: 6, xl: 4, key: "test" },
                        a.createElement(B, { coreNum: 2, history: e }),
                        a.createElement(B, { coreNum: 3, history: e }),
                        a.createElement(B, { coreNum: 4, history: e }),
                        a.createElement(B, { coreNum: 5, history: e }),
                        a.createElement(B, { coreNum: 6, history: e }),
                        a.createElement(B, { coreNum: 7, history: e }),
                        a.createElement(B, { coreNum: 8, history: e })
                      )
                    )
                  );
                }
              }
            ]),
            t
          );
        })(a.PureComponent),
        H = (function(e) {
          function t() {
            var e, n;
            Object(p.a)(this, t);
            for (var a = arguments.length, o = new Array(a), r = 0; r < a; r++)
              o[r] = arguments[r];
            return (
              ((n = Object(h.a)(
                this,
                (e = Object(f.a)(t)).call.apply(e, [this].concat(o))
              )).state = { portList: [] }),
              (n.eventHandler = function(e) {
                if (
                  e.message.includes("Port ") &&
                  e.message.includes(" initialized")
                ) {
                  var t = e.message.replace(" initialized", "");
                  n.setState(function(e) {
                    return { portList: [t].concat(Object(E.a)(e.portList)) };
                  });
                }
              }),
              n
            );
          }
          return (
            Object(b.a)(t, e),
            Object(m.a)(t, [
              {
                key: "componentDidMount",
                value: function() {
                  k("PORT DASHBOARD PAGE", this.eventHandler, !0);
                }
              },
              {
                key: "componentWillUnmount",
                value: function() {
                  w("PORT DASHBOARD PAGE");
                }
              },
              {
                key: "render",
                value: function() {
                  var e = this.state.portList,
                    t = this.props.history;
                  return a.createElement(
                    g.e.Content,
                    null,
                    a.createElement(
                      g.d.Row,
                      null,
                      e.map(function(e) {
                        return a.createElement(
                          g.d.Col,
                          { md: 6, xl: 4, key: e },
                          a.createElement(M, {
                            nfLabel: e,
                            history: t,
                            showMoreInfoButton: !1
                          })
                        );
                      }),
                      0 === e.length && "No ports in use!"
                    )
                  );
                }
              }
            ]),
            t
          );
        })(a.PureComponent);
      var T = function(e) {
          return a.createElement(
            g.g,
            {
              cards: !0,
              striped: !0,
              responsive: !0,
              className: "table-vcenter"
            },
            a.createElement(
              g.g.Header,
              null,
              a.createElement(
                g.g.Row,
                null,
                a.createElement(g.g.ColHeader, null, "Event"),
                a.createElement(g.g.ColHeader, null, "Timestamp")
              )
            ),
            a.createElement(
              g.g.Body,
              null,
              e.events.map(function(e) {
                return a.createElement(
                  g.g.Row,
                  null,
                  a.createElement(g.g.Col, null, e.message),
                  a.createElement(g.g.Col, null, e.timestamp)
                );
              })
            )
          );
        },
        U = (function(e) {
          function t() {
            var e, n;
            Object(p.a)(this, t);
            for (var a = arguments.length, o = new Array(a), r = 0; r < a; r++)
              o[r] = arguments[r];
            return (
              ((n = Object(h.a)(
                this,
                (e = Object(f.a)(t)).call.apply(e, [this].concat(o))
              )).state = { instanceId: null, serviceId: null, core: null }),
              (n.dataCallback = function(e, t) {
                n.setState({
                  instanceId: e.instance_id,
                  serviceId: e.service_id,
                  core: e.core
                });
              }),
              n
            );
          }
          return (
            Object(b.a)(t, e),
            Object(m.a)(t, [
              {
                key: "componentDidMount",
                value: function() {
                  console.log("NF Info Mount: " + this.props.nfLabel),
                    D(
                      "NF ".concat(this.props.nfLabel.split(" - ")[1]),
                      this.dataCallback
                    );
                }
              },
              {
                key: "componentWillUnmount",
                value: function() {
                  console.log("NF Info Unmount: " + this.props.nfLabel),
                    P(
                      "NF ".concat(this.props.nfLabel.split(" - ")[1]),
                      this.dataCallback,
                      null
                    );
                }
              },
              {
                key: "render",
                value: function() {
                  var e = this.state,
                    t = e.serviceId,
                    n = e.instanceId,
                    o = e.core;
                  return a.createElement(
                    g.c,
                    { title: "NF Info" },
                    a.createElement(
                      g.g,
                      { cards: !0 },
                      a.createElement(
                        g.g.Row,
                        null,
                        a.createElement(g.g.Col, null, "Service ID"),
                        a.createElement(
                          g.g.Col,
                          { alignContent: "right" },
                          a.createElement(g.a, { color: "default" }, t)
                        )
                      ),
                      a.createElement(
                        g.g.Row,
                        null,
                        a.createElement(g.g.Col, null, "Instance ID"),
                        a.createElement(
                          g.g.Col,
                          { alignContent: "right" },
                          a.createElement(g.a, { color: "default" }, n)
                        )
                      ),
                      a.createElement(
                        g.g.Row,
                        null,
                        a.createElement(g.g.Col, null, "Core"),
                        a.createElement(
                          g.g.Col,
                          { alignContent: "right" },
                          a.createElement(g.a, { color: "default" }, o)
                        )
                      )
                    )
                  );
                }
              }
            ]),
            t
          );
        })(a.PureComponent),
        z = (function(e) {
          function t() {
            var e, n;
            Object(p.a)(this, t);
            for (var a = arguments.length, o = new Array(a), r = 0; r < a; r++)
              o[r] = arguments[r];
            return (
              ((n = Object(h.a)(
                this,
                (e = Object(f.a)(t)).call.apply(e, [this].concat(o))
              )).state = {
                nfLabel: n.props.match.params.nfLabel,
                eventList: []
              }),
              (n.eventHandler = function(e) {
                var t = parseInt(n.state.nfLabel.split(" - ")[1]),
                  a = e.source;
                a.type &&
                  "MGR" !== a.type &&
                  e.source.instance_id === t &&
                  n.setState(function(t) {
                    return { eventList: Object(E.a)(t.eventList).concat([e]) };
                  });
              }),
              n
            );
          }
          return (
            Object(b.a)(t, e),
            Object(m.a)(t, [
              {
                key: "componentDidMount",
                value: function() {
                  k(
                    "SINGLE NF PAGE ".concat(this.state.nfLabel),
                    this.eventHandler,
                    !0
                  );
                }
              },
              {
                key: "componentWillUnmount",
                value: function() {
                  w("SINGLE NF PAGE ".concat(this.state.nfLabel));
                }
              },
              {
                key: "render",
                value: function() {
                  return a.createElement(
                    g.e.Content,
                    null,
                    a.createElement(
                      g.d.Row,
                      null,
                      a.createElement(
                        g.d.Col,
                        { md: 8, xl: 8 },
                        a.createElement(M, {
                          nfLabel: this.state.nfLabel,
                          showMoreInfoButton: !1,
                          extraContent: a.createElement(T, {
                            events: this.state.eventList
                          })
                        })
                      ),
                      a.createElement(
                        g.d.Col,
                        { sm: 4, lg: 4 },
                        a.createElement(U, { nfLabel: this.state.nfLabel })
                      )
                    )
                  );
                }
              }
            ]),
            t
          );
        })(a.PureComponent);
      var W = function(e) {
        return a.createElement(
          g.c,
          null,
          a.createElement(
            g.c.Header,
            null,
            a.createElement(g.c.Title, null, "Core ", e.coreLabel)
          ),
          a.createElement(g.c.Body, null, e.extraContent)
        );
      };
      var X = function(e) {
          return a.createElement(
            g.g,
            {
              cards: !0,
              striped: !0,
              responsive: !0,
              className: "table-vcenter"
            },
            a.createElement(
              g.g.Body,
              null,
              e.sources.map(function(t) {
                return t.type
                  ? a.createElement(
                      g.g.Row,
                      null,
                      a.createElement(
                        g.g.Col,
                        null,
                        "".concat(t.type, " - ").concat(t.instance_id)
                      ),
                      a.createElement(
                        g.b,
                        {
                          RootComponent: "a",
                          color: "secondary",
                          size: "sm",
                          className: "ml-2",
                          onClick: function() {
                            var n = e.history;
                            n
                              ? n.push(
                                  "/nfs/"
                                    .concat(t.type, " - ")
                                    .concat(t.instance_id)
                                )
                              : console.error("Failed to go to single NF page");
                          }
                        },
                        "View More Info"
                      )
                    )
                  : a.createElement(
                      g.g.Row,
                      null,
                      a.createElement(
                        g.g.Col,
                        null,
                        "".concat(t.msg.split(" ")[0], " Thread")
                      )
                    );
              })
            )
          );
        },
        V = (function(e) {
          function t() {
            var e, n;
            Object(p.a)(this, t);
            for (var a = arguments.length, o = new Array(a), r = 0; r < a; r++)
              o[r] = arguments[r];
            return (
              ((n = Object(h.a)(
                this,
                (e = Object(f.a)(t)).call.apply(e, [this].concat(o))
              )).state = { coreList: {} }),
              (n.eventHandler = function(e) {
                var t = e.source;
                ("NF Ready" === e.message || e.message.includes("Start")) &&
                  n.setState(function(n) {
                    var a = Object(R.a)({}, n.coreList),
                      o = t.core;
                    if (((t.msg = e.message), o in a && a[o].length)) {
                      var r = t.instance_id;
                      r && r !== a[o][0].instance_id && a[o].unshift(t);
                    } else a[o] = [t];
                    return { coreList: a };
                  }),
                  ("NF Stopping" === e.message || e.message.includes("End")) &&
                    n.setState(function(t) {
                      var n,
                        a = Object(R.a)({}, t.coreList),
                        o = e.source.instance_id,
                        r = !1;
                      for (n in a)
                        if (
                          a.hasOwnProperty(n) &&
                          ((a[n] = a[n].filter(function(e) {
                            return !(r = e.instance_id === o);
                          })),
                          r)
                        )
                          break;
                      return (
                        r || console.log("Nothing removed from list!"),
                        0 === a[n].length && delete a[n],
                        { coreList: a }
                      );
                    });
              }),
              n
            );
          }
          return (
            Object(b.a)(t, e),
            Object(m.a)(t, [
              {
                key: "componentDidMount",
                value: function() {
                  k("CORE MAPPINGS PAGE", this.eventHandler, !0);
                }
              },
              {
                key: "componentWillUnmount",
                value: function() {
                  w("CORE MAPPINGS PAGE");
                }
              },
              {
                key: "render",
                value: function() {
                  var e = this.props.history,
                    t = this.state.coreList;
                  return a.createElement(
                    g.e.Content,
                    null,
                    a.createElement(
                      g.d.Row,
                      null,
                      Object.keys(t).map(function(n) {
                        var o = t[n];
                        return o && o.length > 0
                          ? a.createElement(
                              g.d.Col,
                              { md: 6, xl: 4, key: o[0].core },
                              a.createElement(W, {
                                coreLabel: o[0].core,
                                extraContent: a.createElement(X, {
                                  history: e,
                                  sources: o
                                })
                              })
                            )
                          : "";
                      }),
                      (function(e) {
                        for (var t in e) if (e.hasOwnProperty(t)) return !1;
                        return !0;
                      })(t) && "No Cores have Running NFs!"
                    )
                  );
                }
              }
            ]),
            t
          );
        })(a.PureComponent);
      var J = function(e) {
        return "Error404";
      };
      n(37), n(39);
      var Y = function(e) {
        return a.createElement(
          c.a,
          null,
          a.createElement(
            S,
            null,
            a.createElement(
              c.a,
              null,
              a.createElement(
                s.a,
                null,
                a.createElement(i.a, {
                  exact: !0,
                  path: "/",
                  render: function() {
                    return a.createElement(u.a, { to: { pathname: "/nfs" } });
                  }
                }),
                a.createElement(i.a, { exact: !0, path: "/nfs", component: G }),
                a.createElement(i.a, {
                  exact: !0,
                  path: "/nfs/:nfLabel",
                  component: z
                }),
                a.createElement(i.a, {
                  exact: !0,
                  path: "/ports",
                  component: H
                }),
                a.createElement(i.a, {
                  exact: !0,
                  path: "/core-mappings",
                  component: V
                }),
                a.createElement(i.a, { component: J })
              )
            )
          )
        );
      };
      Boolean(
        "localhost" === window.location.hostname ||
          "[::1]" === window.location.hostname ||
          window.location.hostname.match(
            /^127(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/
          )
      );
      l.a.render(
        o.a.createElement(o.a.StrictMode, null, o.a.createElement(Y, null)),
        document.getElementById("root")
      ),
        "serviceWorker" in navigator &&
          navigator.serviceWorker.ready.then(function(e) {
            e.unregister();
          });
    }
  },
  [[23, 2, 1]]
]);
