define(function() {
      var getDrawStyles = function(resource)
        {
          return [
          {
              "id": "gl-draw-point",
              "type": "circle",
              "filter": ["all",
                  ["!in", "$type", "LineString", "Polygon"],
                  ["!=", "mode", "static"],
                  ["!=", "active", 'true']
              ],
              "paint": {
                  "circle-radius": resource.pointsize(),
                  "circle-color": resource.color()
              }
          }, {
            "id": "gl-draw-point-active-halo",
            "type": "circle",
            "filter": ["all", ["!=", "meta", "vertex"],
                ["==", "$type", "Point"],
                ["!=", "mode", "static"],
                ["==", "active", "true"],
            ],
            "paint": {
                "circle-radius": resource.pointsize(),
                "circle-color": "#FFF"
            }
        }, {
              "id": "gl-draw-point-active",
              "type": "circle",
              "layout": {},
              "filter": ["all",
                  ["!in", "$type", "LineString", "Polygon"],
                  ["!=", "mode", "static"],
                  ["==", "active", 'true']
              ],
              "paint": {
                  "circle-radius": resource.pointsize() * 0.75,
                  "circle-color": resource.color()
              }
          },{
              "id": "gl-draw-line",
              "type": "line",
              "filter": ["all", ["==", "$type", "LineString"],
                  ["!=", "mode", "static"]
              ],
              "layout": {
                  "line-cap": "round",
                  "line-join": "round"
              },
              "paint": {
                  "line-color": resource.color(),
                  // "line-dasharray": [0.2, 2],
                  "line-width": resource.linewidth()
              }
          }, {
              "id": "gl-draw-polygon-fill",
              "type": "fill",
              "filter": ["all", ["==", "$type", "Polygon"],
                  ["!=", "mode", "static"]
              ],
              "paint": {
                  "fill-color": resource.color(),
                  "fill-outline-color": resource.color(),
                  "fill-opacity": 0.1
              }
          }, {
              "id": "gl-draw-polygon-stroke-active",
              "type": "line",
              "filter": ["all", ["==", "$type", "Polygon"],
                  ["!=", "mode", "static"]
              ],
              "layout": {
                  "line-cap": "round",
                  "line-join": "round"
              },
              "paint": {
                  "line-color": resource.color(),
                  // "line-dasharray": [0.2, 2],
                  "line-width": resource.linewidth()
              }
          }, {
              "id": "gl-draw-polygon-and-line-vertex-halo-active",
              "type": "circle",
              "filter": ["all", ["==", "meta", "vertex"],
                  ["==", "$type", "Point"],
                  ["!=", "mode", "static"]
              ],
              "paint": {
                  "circle-radius": resource.pointsize(),
                  "circle-color": "#FFF"
              }
          }, {
              "id": "gl-draw-polygon-and-line-vertex-active",
              "type": "circle",
              "filter": ["all", ["==", "meta", "vertex"],
                  ["==", "$type", "Point"],
                  ["!=", "mode", "static"]
              ],
              "paint": {
                  "circle-radius": resource.pointsize() * 0.75,
                  "circle-color": resource.color(),
              }
          }, {
              "id": "gl-draw-polygon-and-line-midpoint-halo-active",
              "type": "circle",
              "filter": ["all", ["==", "meta", "midpoint"],
                  ["==", "$type", "Point"],
                  ["!=", "mode", "static"]
              ],
              "paint": {
                  "circle-radius": resource.pointsize(),
                  "circle-color": "#FFF"
              }
          }, {
              "id": "gl-draw-polygon-and-line-midpoint-active",
              "type": "circle",
              "filter": ["all", ["==", "meta", "midpoint"],
                  ["==", "$type", "Point"],
                  ["!=", "mode", "static"]
              ],
              "paint": {
                  "circle-radius": resource.pointsize() * 0.75,
                  "circle-color": resource.color(),
              }
          }
        ];
       }

      return {getDrawStyles: getDrawStyles};
});
