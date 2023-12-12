from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy import text
from datetime import datetime


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///CVEfixes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Table commits
class commits(db.Model):
    hash = db.Column(db.Integer, primary_key=True)
    repo_url = db.Column(db.String)
    author = db.Column(db.String)
    author_date = db.Column(db.DateTime)
    author_timezone = db.Column(db.String)

    def to_dict(self):
        return {
            'repo_url': self.repo_url,
            'author': self.author,
            'author_date': self.author_date,
            'author_timezone': self.author_timezone
        }

# Table cwe
class cwe(db.Model):
    cwe_id = db.Column(db.String, primary_key=True)
    cwe_name = db.Column(db.String)
    url = db.Column(db.String)

    def to_dict(self):
        return {
            'cwe_id': self.cwe_id,
            'cwe_name': self.cwe_name,
            'url': self.url
        }

# Table fixes    
class fixes(db.Model):
    cve_id = db.Column(db.String, primary_key=True)
    hash = db.Column(db.String)
    repo_url = db.Column(db.String)

    def to_dict(self):
        return {
            'cve_id': self.cve_id,
            'hash': self.hash,
            'repo_url': self.repo_url
        }

@app.route('/')
def index():
    return render_template('index.html', years=range(1999, 2023))


# Commits Table Associated
@app.route('/filter_commits', methods=['GET'])
def filter_commits():
    repo_url = request.args.get('repo_url')
    author = request.args.get('author')
    year = request.args.get('year')  # This will be the year to filter by

    query = commits.query
    if repo_url:
        query = query.filter(commits.repo_url == repo_url)
    if author:
        query = query.filter(commits.author == author)
    if year:
        # Filter by the year substring in the author_date string
        query = query.filter(text("substr(author_date, 1, 4) = :year")).params(year=year)
    # Add more filters as needed

    results = query.all()
    # print(f"Filtering data with repo_url: {repo_url}, author: {author}")
    print(f"Filtered data: {results}")  # Debug print
    return jsonify([item.to_dict() for item in results])


# CWE Table Associated
@app.route('/filter_cwe', methods=['GET'])
def filter_cwe():
    cwe_id = request.args.get('cwe_id')
    cwe_name = request.args.get('cwe_name')
    cwe_url = request.args.get('cwe_url')

    query = cwe.query
    if cwe_id:
        query = query.filter(cwe.cwe_id == cwe_id)
    if cwe_name:
        query = query.filter(cwe.cwe_name.like(f"%{cwe_name}%"))
    if cwe_url:
        query = query.filter(cwe.url == cwe_url)

    results = query.all()
    # print(f"Filtering data with repo_url: {repo_url}, author: {author}")
    print(f"Filtered data: {results}")  # Debug print
    return jsonify([item.to_dict() for item in results])


# Fixes Table Associated
@app.route('/filter_fixes', methods=['GET'])
def filter_fixes():
    cve_id = request.args.get('cve_id')
    hash = request.args.get('hash')
    repo_url = request.args.get('repo_url')

    query = fixes.query
    if cve_id:
        query = query.filter(fixes.cve_id == cve_id)
    if hash:
        query = query.filter(fixes.hash == hash)
    if repo_url:
        query = query.filter(fixes.repo_url == repo_url)

    results = query.all()
    # print(f"Filtering data with repo_url: {repo_url}, author: {author}")
    print(f"Filtered data: {results}")  # Debug print
    return jsonify([item.to_dict() for item in results])

#Data Visualization (Every year chart)
@app.route('/commit_data')
def commit_data():
    # Example: Fetching and counting commits per year from the database
    commit_counts = db.session.query(
        func.strftime('%Y', commits.author_date).label('year'),
        func.count('*').label('count')
    ).group_by('year').all()

    # Convert query result to a dictionary format that Chart.js can use
    data = {
        'labels': [result.year for result in commit_counts],
        'datasets': [{
            'label': 'Commits per Year',
            'data': [result.count for result in commit_counts],
            'backgroundColor': ['red' if result.year == request.args.get('year') else 'blue' for result in commit_counts]
        }]
    }
    return jsonify(data)


#Data Visualization (Every month chart)
@app.route('/commit_data_monthly')
def commit_data_monthly():
    year = request.args.get('year')
    if not year:
        return jsonify({'error': 'Year is required'}), 400

    commit_counts_monthly = db.session.query(
        func.strftime('%m', commits.author_date).label('month'),
        func.count('*').label('count')
    ).filter(func.strftime('%Y', commits.author_date) == year
    ).group_by('month').all()

    # Convert query result to a dictionary format that Chart.js can use
    data = {
        'labels': [result.month for result in commit_counts_monthly],
        'datasets': [{
            'label': f'Commits per Month for {year}',
            'data': [result.count for result in commit_counts_monthly],
            'backgroundColor': 'rgba(54, 162, 235, 0.2)',
            'borderColor': 'rgba(54, 162, 235, 1)',
            'borderWidth': 1
        }]
    }
    return jsonify(data)




if __name__ == '__main__':
    app.run(debug=True, port=5001)
