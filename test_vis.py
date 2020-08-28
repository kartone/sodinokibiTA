import pandas as pd
import numpy as np

from bokeh.io import output_file, output_notebook
from bokeh.plotting import figure, show
from bokeh.models import ColumnDataSource
from bokeh.layouts import row, column, gridplot
from bokeh.models.widgets import Tabs, Panel

output_file('test.html', title = 'My first graph in Bokeh')

fig = figure()

show(fig)