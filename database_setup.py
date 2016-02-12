import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):

	__tablename__ = 'user'

	name = Column(String(250), nullable=False)
	id = Column(Integer, primary_key=True)
	email = Column(String(250), nullable=False)
	picture = Column(String(250))

	@property
	def serialize(self):
	    return {
	    	'name': self.name,
	    	'id': self.id,
	    	'email': self.email,
	    }
	

class Category(Base):

	__tablename__ = 'category'

	name = Column(String(80), nullable=False)
	id = Column(Integer, primary_key=True)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
	    return {
	    	'name': self.name,
	    	'id': self.id,
	    	'user_id': self.user_id,
	    }

	@property
	def serializeXML(self):
	    return "<name>self.name<name><id>self.id</id><user_id>self.user_id/user_id>"

class Item(Base):

	__tablename__ = 'item'

	name = Column(String(80), nullable=False)
	id = Column(Integer, primary_key=True)
	description = Column(String(250), nullable=False)
	category_id = Column(Integer, ForeignKey('category.id'))
	category = relationship(Category)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
	    return {
	    	'category id': self.category_id,
	    	'name': self.name,
	    	'description': self.description,
	    	'id': self.id,
	    	'user_id': self.user_id,
	    }


engine = create_engine('postgresql://catalog:catalog@localhost:5432/catalog')

Base.metadata.create_all(engine)
